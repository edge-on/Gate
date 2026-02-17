#include "Atlas/Atlas.hpp"

Atlas::Atlas() {
    cas = new Cassandra();
    
    if(cas->connect()) {
        std::cout << "ScyllaDB connection is successfully" << std::endl;

        
    } else {
        std::cout << "ScyllaDB connection is not successfully" << std::endl;
    }
}

Atlas::~Atlas() {

}