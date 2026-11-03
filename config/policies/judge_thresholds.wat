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
;; The verdicts are read only after the payload's last `"judge":[`. The
;; agent writes `arguments`, which come before `judge`, so text it puts
;; there cannot be taken for a verdict; inside a JSON string a quote is
;; always escaped, so no string can hold the pattern either. A payload
;; without a `mismatch` verdict is allowed (the harness itself refuses
;; judge failures), and a probability with more digits than one in
;; parts per million can have is denied. With several predicates that
;; use a `mismatch` label, read `predicate_id` before the label as well.
;; Memory: the patterns at 0, the payload from 4096 (see `alloc`).
(module
  (memory (export "memory") 4)
  (data (i32.const 0) "\"label\":\"mismatch\",\"ppm\":")
  (data (i32.const 32) "\"judge\":[")
  (global $next (mut i32) (i32.const 4096))
  (func (export "alloc") (param $len i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $next))
    (global.set $next (i32.add (global.get $next) (local.get $len)))
    (local.get $ptr))
  ;; 1 when the `nlen` bytes at `at` equal the pattern at `noff`.
  (func $matches (param $at i32) (param $noff i32) (param $nlen i32) (result i32)
    (local $j i32)
    (block $equal
      (loop $compare
        (br_if $equal (i32.ge_u (local.get $j) (local.get $nlen)))
        (if (i32.ne
              (i32.load8_u (i32.add (local.get $at) (local.get $j)))
              (i32.load8_u (i32.add (local.get $noff) (local.get $j))))
          (then (return (i32.const 0))))
        (local.set $j (i32.add (local.get $j) (i32.const 1)))
        (br $compare)))
    (i32.const 1))
  ;; Offset just after the last occurrence of the pattern in
  ;; [ptr, ptr + len), or -1.
  (func $after_last (param $ptr i32) (param $len i32) (param $noff i32) (param $nlen i32) (result i32)
    (local $i i32)
    (if (i32.lt_s (local.get $len) (local.get $nlen)) (then (return (i32.const -1))))
    (local.set $i (i32.sub (i32.add (local.get $ptr) (local.get $len)) (local.get $nlen)))
    (block $none
      (loop $scan
        (br_if $none (i32.lt_s (local.get $i) (local.get $ptr)))
        (if (call $matches (local.get $i) (local.get $noff) (local.get $nlen))
          (then (return (i32.add (local.get $i) (local.get $nlen)))))
        (local.set $i (i32.sub (local.get $i) (i32.const 1)))
        (br $scan)))
    (i32.const -1))
  ;; Offset just after the first occurrence of the pattern in
  ;; [from, end), or -1.
  (func $after_first (param $from i32) (param $end i32) (param $noff i32) (param $nlen i32) (result i32)
    (local $i i32)
    (local.set $i (local.get $from))
    (block $none
      (loop $scan
        (br_if $none (i32.gt_s (i32.add (local.get $i) (local.get $nlen)) (local.get $end)))
        (if (call $matches (local.get $i) (local.get $noff) (local.get $nlen))
          (then (return (i32.add (local.get $i) (local.get $nlen)))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $scan)))
    (i32.const -1))
  (func (export "evaluate_v2") (param $ptr i32) (param $len i32) (result i32)
    (local $end i32) (local $at i32) (local $ppm i32) (local $digit i32) (local $digits i32)
    (local.set $end (i32.add (local.get $ptr) (local.get $len)))
    (local.set $at (call $after_last (local.get $ptr) (local.get $len) (i32.const 32) (i32.const 9)))
    (if (i32.lt_s (local.get $at) (i32.const 0)) (then (return (i32.const 0))))
    (local.set $at (call $after_first (local.get $at) (local.get $end) (i32.const 0) (i32.const 25)))
    (if (i32.lt_s (local.get $at) (i32.const 0)) (then (return (i32.const 0))))
    (block $number
      (loop $read
        (br_if $number (i32.ge_u (local.get $at) (local.get $end)))
        (local.set $digit (i32.sub (i32.load8_u (local.get $at)) (i32.const 48)))
        (br_if $number (i32.gt_u (local.get $digit) (i32.const 9)))
        (local.set $digits (i32.add (local.get $digits) (i32.const 1)))
        ;; At most 7 digits (1000000): anything longer is not a
        ;; probability, and denying is the safe answer.
        (if (i32.gt_u (local.get $digits) (i32.const 7)) (then (return (i32.const 1))))
        (local.set $ppm (i32.add (i32.mul (local.get $ppm) (i32.const 10)) (local.get $digit)))
        (local.set $at (i32.add (local.get $at) (i32.const 1)))
        (br $read)))
    (if (i32.eqz (local.get $digits)) (then (return (i32.const 1))))
    (if (i32.gt_u (local.get $ppm) (i32.const 700000)) (then (return (i32.const 1))))
    (if (i32.gt_u (local.get $ppm) (i32.const 300000)) (then (return (i32.const 2))))
    (i32.const 0)))
