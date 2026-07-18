#include <limits>
#include "Aggregators.h"


/* =========== Top LEVEL ===================*/

Aggregator::Aggregator() {

    this->agg_id = MATH_CPP_AGG_MAXX;
    this->aggregator = NULL;
}

Aggregator::~Aggregator() {

   if ( this->aggregator) {
        delete this->aggregator;
        this->aggregator = NULL;
   }
   
    this->agg_id = MATH_CPP_AGG_MAXX;
}

Dtype *
Aggregator::getAggregatedValue () {

    return this->aggregator;
}

void
Aggregator::SetAggregator (Dtype *new_aggregator) {

    this->aggregator = new_aggregator;
}



/* =========== Mid LEVEL ===================*/

AggMax::AggMax() {

    this->agg_id = MATH_CPP_AGG_MAX;
}

AggMax::AggMax(Dtype* aggregator) {

    AggMax();
    this->aggregator = aggregator;
}

AggMax::~AggMax() {

}

void
AggMax::aggregate  (Dtype* new_data) {

    bool rc = *this->aggregator < *new_data;
    if (rc) {
        this->aggregator->SetValue (new_data);
    }
}



AggMin::AggMin() {

    this->agg_id = MATH_CPP_AGG_MIN;
}

AggMin::AggMin(Dtype* aggregator) {

    AggMin();
    this->aggregator = aggregator;
}

AggMin::~AggMin() {

}

void
AggMin::aggregate  (Dtype *new_data) {

    bool rc = *this->aggregator < *new_data;
    if (!rc) {
        this->aggregator->SetValue (new_data);
    }
}


AggSum::AggSum() {

    this->agg_id = MATH_CPP_AGG_SUM;
}

AggSum::AggSum(Dtype* aggregator) {

    AggSum();
    this->aggregator = aggregator;
}

AggSum::~AggSum() {

}

void 
AggSum::aggregate  (Dtype *new_data) {

    *this->aggregator += *new_data;
}


AggCount::AggCount() {

    this->agg_id = MATH_CPP_AGG_COUNT;
    this->aggregator = Dtype::factory (MATH_CPP_INT);
}

AggCount::~AggCount() {}

void
AggCount:: aggregate  (Dtype *new_data) {

    Dtype_INT lobj;
    lobj.dtype.int_val = 1;

    if (new_data) {
        (*this->aggregator) += lobj;
    }
}


/* ========================== factory Method =====================*/

Aggregator *
Aggregator::factory (mexprcpp_agg_t agg_type, mexprcpp_dtypes_t dtype) {

    switch (agg_type) {

        case MATH_CPP_AGG_COUNT:
            return new AggCount();

        case MATH_CPP_AGG_MAX:
            {
                switch (dtype) {
                    case MATH_CPP_INT:
                    {
                        Dtype_INT *dtype = new Dtype_INT();
                        dtype->dtype.int_val = std::numeric_limits<int32_t>::min();
                        return new AggMax (dtype);
                    }
                    case MATH_CPP_DOUBLE:
                    {
                        Dtype_DOUBLE *dtype = new Dtype_DOUBLE();
                        dtype->dtype.d_val = std::numeric_limits<double>::min();
                        return new AggMax (dtype);
                    }
                    case MATH_CPP_DTYPE_INVALID:
                        return new AggMax();
                    default:
                        return new AggMax (Dtype::factory(dtype));
                }
            }
            break;

        case MATH_CPP_AGG_MIN:
            {
                switch (dtype) {
                    case MATH_CPP_INT:
                    {
                        Dtype_INT *dtype = new Dtype_INT();
                        dtype->dtype.int_val = std::numeric_limits<int32_t>::max();
                        return new AggMin (dtype);
                    }
                    case MATH_CPP_DOUBLE:
                    {
                        Dtype_DOUBLE *dtype = new Dtype_DOUBLE();
                        dtype->dtype.d_val = std::numeric_limits<double>::max();
                        return new AggMin (dtype);
                    }
                    case MATH_CPP_DTYPE_INVALID:
                        return new AggMin();                    
                    default:
                        return new AggMin (Dtype::factory(dtype));
                }
            }
            break;

        case MATH_CPP_AGG_AVG:
            return NULL;

        case MATH_CPP_AGG_SUM:
        {
            switch (dtype) {

                case MATH_CPP_DTYPE_INVALID:
                     return new AggSum();
                default:
                    return new AggSum (Dtype::factory(dtype));
            }
        }
            
        case MATH_CPP_AGG_MUL:
           return NULL;

        default:   
            return NULL;
    }
    return NULL;
}