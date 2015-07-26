//===-- llvm/Instruction.h - Instruction class definition -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file contains the declaration of the Instruction class, which is the
/// base class for all of the VM instructions.
///
//===----------------------------------------------------------------------===//

#include "llvm/ADT/MapVector.h"

#include <libxml/xpath.h>
#include <libxml/parser.h>
#include <libxml/xmlschemastypes.h>

using namespace llvm;

namespace taintutil {
  
  /// \brief Parser class to retrieve information for sources, propagations
  ///rules, destinations, and filters from a specification xml file.
  /// For this configuration functionality, it is necessary that clang project
  /// has libxml2 enabled.
  class TaintParser {

  public:
    TaintParser(std::string XMLfilename, std::string XSDfilename);
    ~TaintParser();
    short process();
    
    typedef SmallVector<unsigned, 2> ArgVector;
    
    struct PropagationRule {
      ArgVector SrcArgs;
      ArgVector DstArgs;
      
      inline void addSrcArg(unsigned A) { SrcArgs.push_back(A); }
      inline void addDstArg(unsigned A)  { DstArgs.push_back(A); }
    };
    
    // Type definitions
    static const int SIZE_METHODS = 5;
    static const int SIZE_ARGS = 2;
    
    typedef SmallVector<std::pair<std::string, SmallVector<int, SIZE_ARGS>>,
    SIZE_METHODS> SOURCE;
    typedef SmallVector<std::pair<std::string, PropagationRule>, SIZE_METHODS>
    PROPAGATION;
    typedef SmallVector<std::pair<std::string,SmallVector<int, SIZE_ARGS>>,
    SIZE_METHODS> DESTINATION;
    typedef SmallVector<std::pair<std::string,SmallVector<int, SIZE_ARGS>>,
    SIZE_METHODS> FILTER;
  
    SOURCE getSourceMap();
    PROPAGATION getPropagationRuleMap();
    DESTINATION getDestinationMap();
    FILTER getFilterMap();
    std::string toString();

    enum Errors {
      ValidationError=-2,
      GeneralError=-1
    };
	
  private:
    std::string XMLfilename; // Holds the xml configuration filename.
    std::string XSDfilename; // Holds the schema filename.
                                                    
    SOURCE sourceMap;
    PROPAGATION propagationRuleMap;
    DESTINATION destinationMap;
    FILTER filterMap;
      
    typedef void (TaintParser::*ResultManager)(xmlNodeSetPtr nodes);
      
    /// Executes xpath expression on the xml file, and manage the results using
    /// the given function by parameter.
    bool executeXpathExpression(xmlDocPtr doc, const xmlChar* xpathExpr,
                                  ResultManager resultManagerFunction);

    /// Result manager functions.
    void parseSources(xmlNodeSetPtr nodes);
    void parsePropagationRules(xmlNodeSetPtr nodes);
    void parseDestinations(xmlNodeSetPtr nodes);
    void parseFilters(xmlNodeSetPtr nodes);

    /// Validates the doc against a schema.
    bool validateXMLAgaintSchema(xmlDocPtr doc);
  };
};
