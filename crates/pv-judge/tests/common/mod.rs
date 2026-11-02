//! Shared test fixtures: a toy ONNX classifier built byte for byte.
//!
//! The model casts token ids to floats, masks them, sums them, and maps
//! the sum `s` to logits `[25, s]`. With the tokenizer below (`warn` =
//! 25, `danger` = 50, every other word unknown = 0), text mentioning
//! `danger` scores the second label near 1, `warn` near one half, and
//! anything else near 0.
#![allow(dead_code, clippy::unwrap_used)]

use prost::Message as _;
use pv_judge::local::LocalOnnxConfig;
use pv_judge::{sha256_hex, ModelPin};
use tract_onnx::pb;

pub const TOKENIZER: &str = r#"{
  "version": "1.0",
  "truncation": null,
  "padding": null,
  "added_tokens": [],
  "normalizer": null,
  "pre_tokenizer": {"type": "Whitespace"},
  "post_processor": null,
  "decoder": null,
  "model": {"type": "WordLevel", "vocab": {"[UNK]": 0, "warn": 25, "danger": 50}, "unk_token": "[UNK]"}
}"#;

pub fn tensor_input(name: &str, elem_type: i32) -> pb::ValueInfoProto {
    use pb::tensor_shape_proto::{dimension, Dimension};
    pb::ValueInfoProto {
        name: name.to_owned(),
        r#type: Some(pb::TypeProto {
            value: Some(pb::type_proto::Value::TensorType(pb::type_proto::Tensor {
                elem_type,
                shape: Some(pb::TensorShapeProto {
                    dim: vec![
                        Dimension {
                            value: Some(dimension::Value::DimValue(1)),
                            ..Default::default()
                        },
                        Dimension {
                            value: Some(dimension::Value::DimParam("seq".to_owned())),
                            ..Default::default()
                        },
                    ],
                }),
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub fn node(op: &str, inputs: &[&str], output: &str, attribute: Vec<pb::AttributeProto>) -> pb::NodeProto {
    pb::NodeProto {
        input: inputs.iter().map(|s| (*s).to_owned()).collect(),
        output: vec![output.to_owned()],
        name: output.to_owned(),
        op_type: op.to_owned(),
        attribute,
        ..Default::default()
    }
}

pub fn int_attr(name: &str, value: i64) -> pb::AttributeProto {
    pb::AttributeProto {
        name: name.to_owned(),
        r#type: pb::attribute_proto::AttributeType::Int as i32,
        i: value,
        ..Default::default()
    }
}

pub fn ints_attr(name: &str, values: &[i64]) -> pb::AttributeProto {
    pb::AttributeProto {
        name: name.to_owned(),
        r#type: pb::attribute_proto::AttributeType::Ints as i32,
        ints: values.to_vec(),
        ..Default::default()
    }
}

pub fn float_tensor(name: &str, dims: &[i64], values: &[f32]) -> pb::TensorProto {
    pb::TensorProto {
        name: name.to_owned(),
        dims: dims.to_vec(),
        data_type: pb::tensor_proto::DataType::Float as i32,
        float_data: values.to_vec(),
        ..Default::default()
    }
}

/// ONNX bytes for the toy classifier, with inputs declared in the given order.
pub fn model_bytes(inputs_reversed: bool) -> Vec<u8> {
    let float = pb::tensor_proto::DataType::Float as i32;
    let int64 = pb::tensor_proto::DataType::Int64 as i32;
    let mut input = vec![
        tensor_input("input_ids", int64),
        tensor_input("attention_mask", int64),
    ];
    if inputs_reversed {
        input.reverse();
    }
    let graph = pb::GraphProto {
        name: "toy_judge".to_owned(),
        node: vec![
            node(
                "Cast",
                &["input_ids"],
                "ids_f",
                vec![int_attr("to", i64::from(float))],
            ),
            node(
                "Cast",
                &["attention_mask"],
                "mask_f",
                vec![int_attr("to", i64::from(float))],
            ),
            node("Mul", &["ids_f", "mask_f"], "masked", vec![]),
            node(
                "ReduceSum",
                &["masked"],
                "sum",
                vec![ints_attr("axes", &[1]), int_attr("keepdims", 1)],
            ),
            node("MatMul", &["sum", "w"], "scaled", vec![]),
            node("Add", &["scaled", "b"], "logits", vec![]),
        ],
        initializer: vec![
            float_tensor("w", &[1, 2], &[0.0, 1.0]),
            float_tensor("b", &[2], &[25.0, 0.0]),
        ],
        input,
        output: vec![pb::ValueInfoProto {
            name: "logits".to_owned(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let model = pb::ModelProto {
        ir_version: 7,
        opset_import: vec![pb::OperatorSetIdProto {
            domain: String::new(),
            version: 11,
        }],
        producer_name: "pv-judge-test".to_owned(),
        graph: Some(graph),
        ..Default::default()
    };
    model.encode_to_vec()
}

pub fn config(dir: &std::path::Path, model: &[u8]) -> LocalOnnxConfig {
    let model_path = dir.join("judge.onnx");
    let tokenizer_path = dir.join("tokenizer.json");
    std::fs::write(&model_path, model).unwrap();
    std::fs::write(&tokenizer_path, TOKENIZER).unwrap();
    LocalOnnxConfig {
        model_path,
        tokenizer_path,
        pin: ModelPin::new("toy-judge", "1", sha256_hex(model)).unwrap(),
        tokenizer_sha256: sha256_hex(TOKENIZER.as_bytes()),
        output_labels: vec!["match".to_owned(), "mismatch".to_owned()],
        max_input_tokens: 512,
    }
}
