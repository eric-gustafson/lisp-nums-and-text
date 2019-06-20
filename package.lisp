;;;; Package.lisp 
(defpackage #:numex
  (:shadowing-import-from #:trivia @)
  (:use #:cl #:alexandria #:serapeum
	#:trivia
	)
  (:export
   
   :fixnum-info

   :dotted->vector
   :dotted->list
   :parse-dotted

   :addr->dotted
   
   :dotted->num
   :num->dotted

   :octets-needed
   
   :hexstring->octets
   :parse-machine-hex

   :private-a?

   :octets->num
   :num->octets
   :read-octets

   :string->octet-list
   
   :nbo-hex-string
   :nbo-octet->nbo-integer

   :host8u->net
   :host16u->net
   :host32u->net
   :host64u->net
   
   :read-uint8
   :write-uint8
   :write-uint16
   :write-uint32
   :write-uint64
   :read-uint8
   :read-uint16
   :read-uint32
   :read-uint64

   :*ip-cidr-scanner*
   :*ip-scanner*
   :make-cidr-mask
   )
  )
