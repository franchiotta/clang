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
/// This file contains the declaration of the TaintParser class.
///
//===----------------------------------------------------------------------===//

#include "llvm/ADT/MapVector.h"

#include <libxml/xpath.h>
#include <libxml/parser.h>
#include <libxml/xmlschemastypes.h>

using namespace llvm;

namespace taintutil {
  
  static const int SIZE_METHODS = 5;
  static const int SIZE_ARGS = 2;

  typedef SmallVector<unsigned, 2> ArgVector;
  
  typedef SmallVector<std::pair<std::string, SmallVector<int, SIZE_ARGS>>,
  SIZE_METHODS> SOURCE;
  typedef SmallVector<std::pair<std::string,SmallVector<int, SIZE_ARGS>>,
  SIZE_METHODS> DESTINATION;
  typedef SmallVector<std::pair<std::string,SmallVector<int, SIZE_ARGS>>,
  SIZE_METHODS> FILTER;
  
  ///
  /// \brief Parser class to retrieve configuration taint information from a
  /// specification xml file.
  /// For this functionality, it is needed to have libxml2 enabled.
  ///
  class TaintParser {
  public:
  
    struct PropagationRule {
      ArgVector SrcArgs;
      ArgVector DstArgs;
      
      inline void addSrcArg(unsigned A) { SrcArgs.push_back(A); }
      inline void addDstArg(unsigned A)  { DstArgs.push_back(A); }
    };
  
    typedef SmallVector<std::pair<std::string, PropagationRule>, SIZE_METHODS>
      PROPAGATION;
    
    // Constructors
    TaintParser(std::string XMLfilename, std::string XSDfilename);

    // Destructor
    ~TaintParser();

    ///
    /// \brief Carries out the processing.
    ///
    short process();

    ///
    /// \brief Defines a map (string-list of args) which is an association
    /// between generator function names, and its sources arguments.
    ///
    SOURCE getSourceMap();
    
    ///
    /// \brief Defines a map (string-list of args) which is an association
    /// between propagation function names, and its source arguments, and
    /// destination arguments.
    ///
    PROPAGATION getPropagationRuleMap();
    
    ///
    /// \brief Defines a map (string-list of args) which is an association
    /// between destination function names, and its taget arguments.
    ///
    DESTINATION getDestinationMap();

    ///
    /// \brief Defines a map (string-list of args) which is an association
    /// between sanitizers function names, and its filter arguments.
    ///
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
