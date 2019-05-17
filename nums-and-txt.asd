;; nums-and-txt.asd
(asdf:defsystem #:nums-and-txt
  :name "Nums and Text"
  :description ""
  :author "gustafson.e.gordon@gmail.com"
  :licence "GPL v3"
  :properties
  ((#:author-email . "gustafson.e.gordon@gmail.com")
   (#:date . "2019"))
  :depends-on (#:alexandria
	       #:serapeum
	       #:trivia
	       #:closer-mop)
  :serial t
  :components ((:file "package")
	       (:file "ip"))
  )
