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

#include "includes/TaintExpression.h"
#include "llvm/ADT/MapVector.h"

#include <libxml/xpath.h>
#include <libxml/parser.h>
#include <libxml/xmlschemastypes.h>

using namespace llvm;

namespace taintutil {

static const int SIZE_METHODS = 5;

typedef SmallVector<Source, SIZE_METHODS> SourceList;
typedef SmallVector<Propagator, SIZE_METHODS> PropagationList;
typedef SmallVector<Sink, SIZE_METHODS> DestinationList;
typedef SmallVector<Filter, SIZE_METHODS> FilterList;

///
/// \brief Parser class to retrieve configuration taint information from a
/// specification xml file.
/// For this functionality, it is needed to have libxml2 enabled.
///
class TaintParser {
public:
  // Constructors
  TaintParser(std::string XMLfilename, std::string XSDfilename);

  // Destructor
  ~TaintParser();

  ///
  /// \brief Carries out the processing.
  ///
  short process();

  ///
  /// \brief Defines a list of Sources, which is an association between
  /// generator function names, and its sources arguments.
  ///
  SourceList getSourceList();

  ///
  /// \brief Defines a list of Propagators, which is an association between
  /// propagation function names, and its source arguments, and destination
  /// arguments.
  ///
  PropagationList getPropagationRuleList();

  ///
  /// \brief Defines a list of Sinks, which is an association between
  /// destination function names, and its taget arguments.
  ///
  DestinationList getDestinationList();

  ///
  /// \brief Defines a list of Filters, which is an association between
  /// sanitizers function names, and its filter arguments.
  ///
  FilterList getFilterList();

  std::string toString();

  enum Errors { ValidationError = -2, GeneralError = -1 };

private:
  std::string XMLfilename; // Holds the xml configuration filename.
  std::string XSDfilename; // Holds the schema filename.

  SourceList sourceList;
  PropagationList propagationRuleList;
  DestinationList destinationList;
  FilterList filterList;

  typedef void (TaintParser::*ResultManager)(xmlNodeSetPtr nodes);

  /// Executes xpath expression on the xml file, and manage the results using
  /// the given function by parameter.
  bool executeXpathExpression(xmlDocPtr doc, const xmlChar *xpathExpr,
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
