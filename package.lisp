;;;; Package.lisp 
(defpackage #:nums-and-txt
  (:shadowing-import-from #:trivia @)
  (:use #:cl #:alexandria #:serapeum
	#:trivia)
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
   )
  )
