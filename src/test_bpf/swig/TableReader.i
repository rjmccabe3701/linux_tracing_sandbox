%module TableReader
%include "typemaps.i"
%include "std_vector.i"
%include "stdint.i"
%{
   /* #include "../common.h" */
   /* This isn't processed by the swig preprocessor */
   #include "TableReader.h"
%}

%include "TableReader.h"
namespace std {
   %template(TableVec) std::vector<TrafficCounters>;
}

/* Don't know how to get rid of this shit for the vector elements*/
/* <TableReader.TrafficCounters; proxy of <Swig Object of type 'std::vector< TrafficCounters >::value_type *' at 0x7fa8af00b930> > */
