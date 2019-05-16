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

   :dotted->num
   :num->dotted
   )
  )
