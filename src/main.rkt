#lang racket/base
(require racket/list racket/cmdline "dmarc.rkt")
(define (usage)
  (eprintf "usage: dmarc-report PATH [--tsv] [--fail-on high|medium]\nExit: 0 ok, 1 findings at or above --fail-on, 2 bad input.\n")
  (exit 2))
(define args (vector->list (current-command-line-arguments)))
(define tsv #f) (define fail #f) (define path #f)
(let loop ([a args])
  (cond [(null? a) (void)]
        [(equal? (car a) "--tsv") (set! tsv #t) (loop (cdr a))]
        [(and (equal? (car a) "--fail-on") (pair? (cdr a)) (member (cadr a) '("high" "medium")))
         (set! fail (string->symbol (cadr a))) (loop (cddr a))]
        [(and (positive? (string-length (car a))) (char=? (string-ref (car a) 0) #\-)) (usage)]
        [path (usage)]
        [else (set! path (car a)) (loop (cdr a))]))
(unless path (usage))
(unless (or (file-exists? path) (directory-exists? path))
  (eprintf "error: no such file or directory: ~a\n" path) (exit 2))
(define-values (reports warnings) (load-reports path))
(when (null? reports)
  (for ([w warnings]) (eprintf "warning: ~a\n" w))
  (eprintf "error: no readable DMARC reports in ~a\n" path) (exit 2))
(define fs (analyse reports))
(display (if tsv (render-tsv fs (length reports)) (render-text fs (length reports) warnings)))
(exit (cond [(not fail) 0]
            [(eq? fail 'high) (if (ormap (λ (f) (eq? (finding-severity f) 'high)) fs) 1 0)]
            [else (if (ormap (λ (f) (memq (finding-severity f) '(high medium))) fs) 1 0)]))
