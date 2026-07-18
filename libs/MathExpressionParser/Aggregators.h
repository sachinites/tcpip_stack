#ifndef __AGGREGATORS__
#define __AGGREGATORS__

#include "Dtype.h"
#include "MExprcppEnums.h"

/* =========== Top LEVEL ===================*/


class Aggregator {

    private:

    protected:
        mexprcpp_agg_t agg_id;
        Aggregator();

    public:
        Dtype *aggregator;
        virtual ~Aggregator();
        virtual void aggregate (Dtype* new_data) = 0;
        static Aggregator *factory (mexprcpp_agg_t agg_type, mexprcpp_dtypes_t dtype);
        Dtype *getAggregatedValue ();
        void SetAggregator (Dtype *);
}; 


/* =========== Mid LEVEL ===================*/


class AggMax : public Aggregator {

    private:

    protected:
    public:
        AggMax( );
        AggMax(Dtype* aggregator);
        ~AggMax();
        virtual void aggregate  (Dtype* new_data) override;
} ;

class AggMin : public Aggregator {

    private:

    protected:
       
    public:
         AggMin( );
        AggMin(Dtype* aggregator);
        ~AggMin();
        virtual void aggregate  (Dtype* new_data) override;
} ;


class AggSum : public Aggregator {

    private:

    protected:
       
    public:
         AggSum();
         AggSum(Dtype* aggregator);
        ~AggSum();
        virtual void aggregate  (Dtype* new_data) override;
} ;



class AggCount : public Aggregator {

    private:

    protected:
        
    public:
        AggCount();
        ~AggCount();
        virtual void aggregate  (Dtype* new_data) override;
};


#endif 
