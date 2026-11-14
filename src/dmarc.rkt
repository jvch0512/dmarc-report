#lang racket/base
;; dmarc-report core: parse DMARC aggregate XML, aggregate by source, produce findings.
(require racket/list racket/string racket/file racket/path racket/format xml xml/path)
(provide (struct-out rec) (struct-out report) (struct-out src) (struct-out finding)
         parse-report load-reports aggregate analyse render-text render-tsv severity-rank pass-rate)

(struct rec (ip count disposition dkim spf from) #:transparent)
(struct report (org id domain p sp pct recs) #:transparent)
(struct src (ip total both dkim-only spf-only fail delivered-fail) #:transparent)
(struct finding (severity rule where message) #:transparent)

(define (text x) (if (string? x) (string-trim x) ""))
(define (one xe path) (let ([l (se-path*/list (list path) xe)]) (if (null? l) "" (text (car l)))))
(define (num s) (or (string->number s) 0))

;; parse-report: string (XML text) -> report, or raises exn:fail on malformed input
(define (parse-report str)
  (define xe (xml->xexpr (document-element (read-xml (open-input-string str)))))
  (unless (eq? (car xe) 'feedback) (error "not a DMARC aggregate report"))
  (define pol '())
  (define recs
    (for/list ([r (in-list (filter (λ (x) (and (pair? x) (eq? (car x) 'record))) xe))])
      (rec (one r 'source_ip) (num (one r 'count)) (one r 'disposition)
           (one r 'dkim) (one r 'spf) (one r 'header_from))))
  (when (null? recs) (error "report has no records"))
  (report (one xe 'org_name) (one xe 'report_id) (one xe 'domain)
          (one xe 'p) (one xe 'sp) (let ([n (one xe 'pct)]) (if (string=? n "") 100 (num n)))
          recs))

;; load-reports: path -> (values reports warnings)
(define (load-reports path)
  (define files
    (cond [(directory-exists? path)
           (sort (for/list ([f (in-directory path)] #:when (regexp-match? #rx"[.]xml$" (path->string f))) (path->string f)) string<?)]
          [else (list path)]))
  (for/fold ([rs '()] [ws '()] #:result (values (reverse rs) (reverse ws))) ([f files])
    (with-handlers ([exn:fail? (λ (e) (values rs (cons (format "~a: ~a" (file-name-from-path f) (exn-message e)) ws)))])
      (values (cons (parse-report (file->string f)) rs) ws))))

(define (ok? s) (string=? s "pass"))

;; aggregate: reports -> list of src sorted by ip
(define (aggregate reports)
  (define h (make-hash))
  (for* ([r reports] [c (report-recs r)])
    (define cur (hash-ref h (rec-ip c) (vector 0 0 0 0 0 0)))
    (define n (rec-count c))
    (define d (ok? (rec-dkim c))) (define s (ok? (rec-spf c)))
    (vector-set! cur 0 (+ (vector-ref cur 0) n))
    (cond [(and d s) (vector-set! cur 1 (+ (vector-ref cur 1) n))]
          [d (vector-set! cur 2 (+ (vector-ref cur 2) n))]
          [s (vector-set! cur 3 (+ (vector-ref cur 3) n))]
          [else (vector-set! cur 4 (+ (vector-ref cur 4) n))
                (when (string=? (rec-disposition c) "none") (vector-set! cur 5 (+ (vector-ref cur 5) n)))])
    (hash-set! h (rec-ip c) cur))
  (sort (for/list ([(ip v) h]) (apply src ip (vector->list v))) string<? #:key src-ip))

(define (pass-rate reports)
  (define-values (tot ok)
    (for*/fold ([t 0] [o 0]) ([r reports] [c (report-recs r)])
      (values (+ t (rec-count c)) (+ o (if (or (ok? (rec-dkim c)) (ok? (rec-spf c))) (rec-count c) 0)))))
  (if (zero? tot) 100.0 (* 100.0 (/ ok tot))))

(define (severity-rank s) (case s [(high) 0] [(medium) 1] [(low) 2] [else 3]))

;; analyse: reports -> findings sorted by severity
(define (analyse reports)
  (define srcs (aggregate reports))
  (define domains (remove-duplicates (map report-domain reports)))
  (define fs '())
  (define (add! f) (set! fs (cons f fs)))
  (for ([s srcs])
    (cond
      [(> (src-delivered-fail s) 0)
       (add! (finding 'high "DMARC101" (src-ip s)
                      (format "~a messages failed SPF and DKIM alignment and were delivered anyway (~a in total from this source): spoofing or a sender you forgot to authorise"
                              (src-delivered-fail s) (src-total s))))]
      [(> (src-fail s) 0)
       (add! (finding 'medium "DMARC101" (src-ip s)
                      (format "~a messages failed SPF and DKIM alignment (blocked by the receiver)" (src-fail s))))])
    (when (and (zero? (src-fail s)) (or (> (src-dkim-only s) 0) (> (src-spf-only s) 0)))
      (add! (finding 'medium "DMARC102" (src-ip s)
                      (format "~a of ~a messages pass through ~a only: ~a"
                              (+ (src-dkim-only s) (src-spf-only s)) (src-total s)
                              (if (> (src-spf-only s) 0) "SPF" "DKIM")
                              (if (> (src-spf-only s) 0) "forwarding will break alignment, add DKIM signing" "SPF is not aligned, check the envelope sender"))))))
  (for ([d domains])
    (define rs (filter (λ (r) (string=? (report-domain r) d)) reports))
    (define p (report-p (car rs)))
    (define pct (apply min (map report-pct rs)))
    (define failing (for*/sum ([r rs] [c (report-recs r)]) (if (or (ok? (rec-dkim c)) (ok? (rec-spf c)) (not (string=? (rec-disposition c) "none"))) 0 (rec-count c))))
    (when (and (string=? p "none") (> failing 0))
      (add! (finding 'medium "DMARC103" d (format "policy is p=none (monitoring only) while ~a messages that fail alignment are delivered" failing))))
    (when (and (not (string=? p "none")) (< pct 100))
      (add! (finding 'low "DMARC104" d (format "enforcement applies to ~a% of mail only (pct=~a)" pct pct))))
    (add! (finding 'info "DMARC105" d (format "~a% of ~a messages pass DMARC (policy p=~a)"
                                                (~r (pass-rate rs) #:precision '(= 1))
                                                (for*/sum ([r rs] [c (report-recs r)]) (rec-count c)) p))))
  (sort (reverse fs) < #:key (λ (f) (severity-rank (finding-severity f)))))

(define (render-text fs nreports warnings)
  (string-append
   (format "~a reports, ~a findings\n" nreports (length fs))
   (apply string-append (for/list ([w warnings]) (format "warning: ~a\n" w)))
   (apply string-append
          (for/list ([f fs])
            (format "~a ~a ~a\n          ~a\n" (string-upcase (symbol->string (finding-severity f))) (finding-rule f) (finding-where f) (finding-message f))))))

(define (render-tsv fs nreports)
  (string-append
   (format "# ~a reports, ~a findings\n" nreports (length fs))
   (apply string-append
          (for/list ([f fs])
            (format "~a\t~a\t~a\t~a\n" (finding-severity f) (finding-rule f) (finding-where f) (finding-message f))))))
