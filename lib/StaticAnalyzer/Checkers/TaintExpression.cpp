//
//  TaintMethod.cpp
//
//  Implementation of TaintExpression.h
//

#include "includes/TaintExpression.h"


// TaintExpression implementation
std::string taintutil::TaintExpression::getName() const{
  return Name;
}

std::string taintutil::TaintExpression::getCalleeType() const{
  return CalleeType;
}

void taintutil::TaintExpression::setName(std::string Name){
  this->Name=Name;
}

void taintutil::TaintExpression::setCalleeType(std::string CalleeType){
  this->CalleeType=CalleeType;
}

// Source implementation
taintutil::ArgVector& taintutil::Source::getArgs(){
  return ArgSource;
}

void taintutil::Source::addArgument(int Arg){
  ArgSource.push_back(Arg);
}

std::string taintutil::Source::toString() const {
  std::string str = "Name: " + getName() + "  Args: [";
  for (ArgVector::const_iterator I = this->ArgSource.begin(),
       E = ArgSource.end();
       I != E; ++I) {
    int arg = *I;
    str += std::to_string(arg) + ((I+1!=E)? ", " : "");
  }
  str += "]  Calle Type: "+getCalleeType()+".";
  return str;
}

// Propagator implementation
taintutil::ArgVector& taintutil::Propagator::getSourceArgs(){
  return Sources;
}

taintutil::ArgVector& taintutil::Propagator::getDestArgs(){
  return Destinations;
}

void taintutil::Propagator::addSourceArg(int Arg){
  Sources.push_back(Arg);
}

void taintutil::Propagator::addDestArg(int Arg){
  Destinations.push_back(Arg);
}

std::string taintutil::Propagator::toString() const {
  std::string str = "Name: " + getName() + "  Source Args: [";
  for (ArgVector::const_iterator I = Sources.begin(),
       E = Sources.end();
       I != E; ++I) {
    int arg = *I;
    str += std::to_string(arg) + ((I+1!=E)? ", " : "");
  }
  str = str + "]  Destination Args: [";
  for (ArgVector::const_iterator I = Destinations.begin(),
       E = Destinations.end();
       I != E; ++I) {
    int arg = *I;
    str += std::to_string(arg) + ((I+1!=E)? ", " : "");
  }
  str += "]  Calle Type: "+getCalleeType()+".";
  return str;
}

// Sink implementation
taintutil::ArgVector& taintutil::Sink::getArgs(){
  return ArgSink;
}

void taintutil::Sink::addArgument(int Arg){
  ArgSink.push_back(Arg);
}

std::string taintutil::Sink::toString() const {
  std::string str = "Name: " + getName() + "  Args: [";
  for (ArgVector::const_iterator I = ArgSink.begin(),
       E = ArgSink.end();
       I != E; ++I) {
    int arg = *I;
    str = str + std::to_string(arg) + ((I+1!=E)? ", " : "");
  }
  str += "]  Calle Type: "+getCalleeType()+".";
  return str;
}

// Filter implementation
taintutil::ArgVector& taintutil::Filter::getArgs(){
  return ArgFilter;
}

void taintutil::Filter::addArgument(int Arg){
  ArgFilter.push_back(Arg);
}

std::string taintutil::Filter::toString() const {
  std::string str = "Name: " + getName() + "  Args: [";
  for (ArgVector::const_iterator I = ArgFilter.begin(),
       E = ArgFilter.end();
       I != E; ++I) {
    int arg = *I;
    str += std::to_string(arg) + ((I+1!=E)? ", " : "");
  }
  str += "]  Calle Type: "+getCalleeType()+".";
  return str;
}
