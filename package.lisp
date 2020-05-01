;;;; Package.lisp 
(defpackage #:numex
  ;;(:shadowing-import-from #:optima @)
  (:use #:cl #:alexandria #:serapeum
	#:optima #:cffi
	)
  (:export
   
   :fixnum-info

   :dotted->vector
   :dotted->list
   :parse-dotted

   :->dotted
   
   :dotted->num
   :num->dotted

   :octets-needed

   :hostnum->octets
   :hexstring->octets
   :parse-machine-hex

   :private-a?

   :octets->num
   :seq->num
   :->num 
   :num->octets
   :read-octets

   :string->octet-list
   
   :nbo-hex-string
   :octet-list->hexstr
   :octet-list->hexstr/colons
   
   :nbo-octet->nbo-integer

   
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
   :*hexstr-scanner*

   :make-cidr-mask
   :ip-cidr->net

   :ip-net
   :first-ip :last-ip
   :netmask-bits
   :address-bits
   :cidr-subnets
   :cidr-net
   :cidr-bcast
   :cidr-net-increment
   )
  )
