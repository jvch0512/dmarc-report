#lang racket/base
(require rackunit racket/file racket/port racket/system racket/string racket/runtime-path "../src/dmarc.rkt")
(define-runtime-path root "..")

(define (xml #:p [p "none"] #:pct [pct 100] . recs)
  (string-append "<?xml version=\"1.0\"?><feedback><report_metadata><org_name>r.test</org_name><report_id>1</report_id></report_metadata>"
                 "<policy_published><domain>d.test</domain><p>" p "</p><pct>" (number->string pct) "</pct></policy_published>"
                 (apply string-append recs) "</feedback>"))
(define (r ip n disp dkim spf)
  (format "<record><row><source_ip>~a</source_ip><count>~a</count><policy_evaluated><disposition>~a</disposition><dkim>~a</dkim><spf>~a</spf></policy_evaluated></row><identifiers><header_from>d.test</header_from></identifiers></record>" ip n disp dkim spf))
(define (fs . xmls) (analyse (map parse-report xmls)))
(define (rules l) (sort (map finding-rule l) string<?))
(define (has l rule sev [where #f])
  (for/or ([f l]) (and (equal? (finding-rule f) rule) (eq? (finding-severity f) sev) (or (not where) (equal? (finding-where f) where)))))

;; parsing
(define rp (parse-report (xml (r "192.0.2.1" 5 "none" "pass" "fail"))))
(check-equal? (report-domain rp) "d.test")
(check-equal? (report-p rp) "none")
(check-equal? (report-pct rp) 100)
(check-equal? (report-org rp) "r.test")
(check-equal? (length (report-recs rp)) 1)
(check-equal? (rec-ip (car (report-recs rp))) "192.0.2.1")
(check-equal? (rec-count (car (report-recs rp))) 5)
(check-equal? (rec-spf (car (report-recs rp))) "fail")
(check-equal? (report-pct (parse-report (xml #:pct 50 (r "192.0.2.1" 1 "none" "pass" "pass")))) 50)
(check-exn exn:fail? (λ () (parse-report "not xml")))
(check-exn exn:fail? (λ () (parse-report "<other/>")))
(check-exn exn:fail? (λ () (parse-report (xml))))
(check-exn exn:fail? (λ () (parse-report "<feedback><record>")))

;; aggregation
(define agg (aggregate (list (parse-report (xml (r "1.1.1.1" 10 "none" "pass" "pass") (r "1.1.1.1" 5 "none" "pass" "fail")
                                                (r "1.1.1.1" 2 "none" "fail" "pass") (r "1.1.1.1" 3 "none" "fail" "fail")
                                                (r "1.1.1.1" 1 "reject" "fail" "fail") (r "2.2.2.2" 4 "none" "pass" "pass"))))))
(check-equal? (length agg) 2)
(check-equal? (src-total (car agg)) 21)
(check-equal? (src-both (car agg)) 10)
(check-equal? (src-dkim-only (car agg)) 5)
(check-equal? (src-spf-only (car agg)) 2)
(check-equal? (src-fail (car agg)) 4)
(check-equal? (src-delivered-fail (car agg)) 3)
(check-equal? (map src-ip agg) '("1.1.1.1" "2.2.2.2"))

;; pass rate
(check-= (pass-rate (list (parse-report (xml (r "1.1.1.1" 9 "none" "pass" "pass") (r "2.2.2.2" 1 "none" "fail" "fail"))))) 90.0 0.001)
(check-= (pass-rate '()) 100.0 0.001)

;; rules
(define clean (fs (xml (r "192.0.2.1" 10 "none" "pass" "pass"))))
(check-equal? (rules clean) '("DMARC105"))
(check-true (has (fs (xml (r "192.0.2.9" 3 "none" "fail" "fail"))) "DMARC101" 'high "192.0.2.9"))
(check-true (has (fs (xml #:p "reject" (r "192.0.2.9" 3 "reject" "fail" "fail"))) "DMARC101" 'medium "192.0.2.9"))
(check-false (has (fs (xml #:p "reject" (r "192.0.2.9" 3 "reject" "fail" "fail"))) "DMARC101" 'high))
(check-true (has (fs (xml (r "192.0.2.9" 3 "none" "pass" "fail"))) "DMARC102" 'medium))
(check-false (has (fs (xml (r "192.0.2.9" 3 "none" "pass" "pass"))) "DMARC102" 'medium))
(check-true (has (fs (xml (r "192.0.2.9" 3 "none" "fail" "fail"))) "DMARC103" 'medium "d.test"))
(check-false (has (fs (xml (r "192.0.2.9" 3 "none" "pass" "pass"))) "DMARC103" 'medium))
(check-false (has (fs (xml #:p "reject" (r "192.0.2.9" 3 "none" "fail" "fail"))) "DMARC103" 'medium))
(check-true (has (fs (xml #:p "quarantine" #:pct 25 (r "192.0.2.9" 3 "none" "pass" "pass"))) "DMARC104" 'low "d.test"))
(check-false (has (fs (xml #:p "none" #:pct 25 (r "192.0.2.9" 3 "none" "pass" "pass"))) "DMARC104" 'low))
;; two reports are merged per source
(define two (fs (xml (r "192.0.2.9" 2 "none" "fail" "fail")) (xml (r "192.0.2.9" 3 "none" "fail" "fail"))))
(check-true (for/or ([f two]) (regexp-match? #rx"^5 messages" (finding-message f))))
;; ordering: high first
(check-eq? (finding-severity (car (fs (xml (r "1.1.1.1" 1 "none" "pass" "fail") (r "2.2.2.2" 1 "none" "fail" "fail"))))) 'high)
;; rejected mail does not count as delivered failure
(check-false (has (fs (xml (r "192.0.2.9" 3 "reject" "fail" "fail"))) "DMARC103" 'medium))

;; rendering
(define out (render-text clean 1 '("x.xml: bad")))
(check-true (regexp-match? #rx"^1 reports, 1 findings" out))
(check-true (regexp-match? #rx"warning: x.xml: bad" out))
(define tsv (render-tsv (fs (xml (r "192.0.2.9" 3 "none" "fail" "fail"))) 1))
(check-true (regexp-match? #rx"^# 1 reports, 3 findings\nhigh\tDMARC101\t192.0.2.9\t" tsv))
(check-equal? (severity-rank 'high) 0)
(check-true (< (severity-rank 'medium) (severity-rank 'low)))

;; loading
(define tmp (make-temporary-file "dmarc~a" 'directory))
(display-to-file (xml (r "192.0.2.1" 1 "none" "pass" "pass")) (build-path tmp "a.xml"))
(display-to-file "garbage" (build-path tmp "b.xml"))
(display-to-file "ignored" (build-path tmp "c.txt"))
(let-values ([(rs ws) (load-reports (path->string tmp))])
  (check-equal? (length rs) 1)
  (check-equal? (length ws) 1)
  (check-true (regexp-match? #rx"b.xml" (car ws))))
(let-values ([(rs ws) (load-reports (path->string (build-path tmp "a.xml")))])
  (check-equal? (length rs) 1))
(delete-directory/files tmp)
;; XML entities are not fetched
(check-exn exn:fail? (λ () (parse-report "<!DOCTYPE feedback [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><feedback>&x;</feedback>")))

;; CLI
(define (cli . args)
  (current-directory root)
  (define-values (sp o i e) (apply subprocess #f #f #f (path->string (build-path root "bin" "dmarc-report")) args))
  (close-output-port i) (port->string o) (port->string e) (subprocess-wait sp) (subprocess-status sp))
(check-equal? (cli "examples/reports") 0)
(check-equal? (cli "examples/reports" "--fail-on" "high") 1)
(check-equal? (cli "examples/reports" "--fail-on" "medium") 1)
(check-equal? (cli "/no/such/path") 2)
(check-equal? (cli) 2)
(check-equal? (cli "examples/reports" "--bogus") 2)
(check-equal? (cli "examples/reports" "--fail-on" "nope") 2)
