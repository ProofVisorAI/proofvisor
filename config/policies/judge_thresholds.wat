;; Example judge-aware policy (policy interface version 2).
;;
;; It reads the semantic judge's verdicts and applies the build
;; specification's example thresholds to the `mismatch` label of
;; `arg_matches_task@1`: deny above 0.7, ask for approval above 0.3,
;; allow otherwise. Both bounds are strict. The harness's own
;; `[[judge.thresholds]]` do the same without WASM; use a policy like
;; this one when a decision needs more than a threshold per label.
;;
;; The host writes `{"tool": ..., "arguments": ..., "judge": [...]}`,
;; with probabilities as integer parts per million; return 0 to allow,
;; 1 to deny, 2 to ask. Add the file to `wasm_policy_paths` to use it.
;; This example finds the first `"label":"mismatch","ppm":` in the
;; payload; with several judged predicates, check `predicate_id` too.
(module
  (memory (export "memory") 4)
  (data (i32.const 0) "\"label\":\"mismatch\",\"ppm\":")
  (global $next (mut i32) (i32.const 4096))
  (func (export "alloc") (param $len i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $next))
    (global.set $next (i32.add (global.get $next) (local.get $len)))
    (local.get $ptr))
  ;; Offset just after the 25-byte needle at 0, or -1.
  (func $after (param $ptr i32) (param $len i32) (result i32)
    (local $i i32) (local $j i32) (local $end i32)
    (local.set $end (i32.sub (i32.add (local.get $ptr) (local.get $len)) (i32.const 25)))
    (local.set $i (local.get $ptr))
    (block $done
      (loop $scan
        (br_if $done (i32.gt_s (local.get $i) (local.get $end)))
        (local.set $j (i32.const 0))
        (block $miss
          (loop $cmp
            (br_if $miss (i32.ne
              (i32.load8_u (i32.add (local.get $i) (local.get $j)))
              (i32.load8_u (local.get $j))))
            (local.set $j (i32.add (local.get $j) (i32.const 1)))
            (if (i32.eq (local.get $j) (i32.const 25))
              (then (return (i32.add (local.get $i) (i32.const 25)))))
            (br $cmp)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $scan)))
    (i32.const -1))
  (func (export "evaluate_v2") (param $ptr i32) (param $len i32) (result i32)
    (local $at i32) (local $ppm i32) (local $digit i32)
    (local.set $at (call $after (local.get $ptr) (local.get $len)))
    (if (i32.lt_s (local.get $at) (i32.const 0)) (then (return (i32.const 0))))
    (block $end
      (loop $digits
        (local.set $digit (i32.sub (i32.load8_u (local.get $at)) (i32.const 48)))
        (br_if $end (i32.gt_u (local.get $digit) (i32.const 9)))
        (local.set $ppm (i32.add (i32.mul (local.get $ppm) (i32.const 10)) (local.get $digit)))
        (local.set $at (i32.add (local.get $at) (i32.const 1)))
        (br $digits)))
    (if (i32.gt_u (local.get $ppm) (i32.const 700000)) (then (return (i32.const 1))))
    (if (i32.gt_u (local.get $ppm) (i32.const 300000)) (then (return (i32.const 2))))
    (i32.const 0)))

