//
//  TaintExpression.h
//
//  Defines the classes that represents Souces, Propagators, Sinks and Filters.
//  These classes are used to hold the information retrieved from the xml
//  configuration files.
//

#ifndef __LLVM__TaintExpression__
#define __LLVM__TaintExpression__

#include "llvm/ADT/MapVector.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace taintutil {
static const int SIZE_ARGS = 2;
static const char* CALLEETYPEALL = "all";
typedef SmallVector<unsigned, SIZE_ARGS> ArgVector;

class TaintExpression {
private:
  std::string Name;
  std::string CalleeType;

protected:
  TaintExpression(){}
  
  virtual ~TaintExpression() {}
  
  TaintExpression(std::string Name, std::string CalleeType)
      : Name(Name), CalleeType(CalleeType) {}

public:
  std::string getName() const;
  
  std::string getCalleeType() const;
  
  void setName(std::string Name);
  
  void setCalleeType(std::string CalleeType);
  
  virtual std::string toString() const = 0;
};

class Source : public TaintExpression {
private:
  ArgVector ArgSource;

public:
  Source() { this->ArgSource = ArgVector(); }
  
  Source(std::string Name, std::string CalleeType, ArgVector ArgSource)
      : TaintExpression(Name, CalleeType) {
    this->ArgSource = ArgSource;
  }
  
  ~Source() {}
  
  ArgVector &getArgs();
  
  void addArgument(int Arg);
  
  std::string toString() const;
};

class Propagator : public TaintExpression {
private:
  ArgVector Sources;
  ArgVector Destinations;

public:
  Propagator() {
    Sources = ArgVector();
    Destinations = ArgVector();
  }
  
  Propagator(std::string Name, std::string CalleeType, ArgVector Sources,
             ArgVector Destinations)
      : TaintExpression(Name, CalleeType) {
    this->Sources = Sources;
    this->Destinations = Destinations;
  }
  
  ~Propagator() {}
  
  ArgVector &getSourceArgs();
  
  ArgVector &getDestArgs();
  
  void addSourceArg(int Arg);
  
  void addDestArg(int Arg);
  
  std::string toString() const;
};

class Sink : public TaintExpression {
private:
  ArgVector ArgSink;

public:
  Sink() { ArgSink = ArgVector(); }
  
  Sink(std::string Name, std::string CalleeType, ArgVector ArgSink)
      : TaintExpression(Name, CalleeType) {
    this->ArgSink = ArgSink;
  }
  
  ~Sink() {}
  
  ArgVector &getArgs();
  
  void addArgument(int Arg);
  
  std::string toString() const;
};

class Filter : public TaintExpression {
private:
  ArgVector ArgFilter;

public:
  Filter() { ArgFilter = ArgVector(); }
  
  Filter(std::string Name, std::string CalleeType, ArgVector ArgFilter)
      : TaintExpression(Name, CalleeType) {
    this->ArgFilter = ArgFilter;
  }
  
  ~Filter() {}
  
  ArgVector &getArgs();
  
  void addArgument(int Arg);
  
  std::string toString() const;
};
}

#endif
