;; numex.asd
(asdf:defsystem #:numex
  :name "Numerical Exchange"
  :description ""
  :author "gustafson.e.gordon@gmail.com"
  :licence "GPL v3"
  :properties
  ((#:author-email . "gustafson.e.gordon@gmail.com")
   (#:date . "2019"))
  :depends-on (#:alexandria
	       #:serapeum
	       #:trivia
	       #:trivia.ppcre
	       #:closer-mop)
  :serial t
  :components ((:file "package")
	       (:file "cidr")
	       (:file "ip")
	       (:file "pnets")
	       )
  )
