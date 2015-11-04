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
/// Implementation of TaintParser class.
///
//===----------------------------------------------------------------------===//

#include "includes/TaintParser.h"
using namespace llvm;

namespace taintutil {

// ----------------------------- //
//     Parser implementation     //
// ----------------------------- //

TaintParser::TaintParser(std::string XMLfilename, std::string XSDfilename) {
  this->XMLfilename = XMLfilename;
  this->XSDfilename = XSDfilename;
  this->sourceList = SourceList();
  this->propagationRuleList = PropagationList();
  this->destinationList = DestinationList();
  this->filterList = FilterList();
}
TaintParser::~TaintParser() {}

short TaintParser::process() {
  xmlDocPtr doc;

  // Load XML document
  doc = xmlParseFile(this->XMLfilename.data());
  if (doc == NULL) {
    return Errors::GeneralError;
  }

  if (!validateXMLAgaintSchema(doc))
    return Errors::ValidationError;

  // Init libxml
  xmlInitParser();
  LIBXML_TEST_VERSION

  // Do the main job
  if (!executeXpathExpression(doc,
                              BAD_CAST "/TaintChecker/TaintSources/TaintSource",
                              &TaintParser::parseSources))
    return Errors::GeneralError;

  if (!executeXpathExpression(doc, BAD_CAST
                              "/TaintChecker/PropagationRules/PropagationRule",
                              &TaintParser::parsePropagationRules))
    return Errors::GeneralError;

  if (!executeXpathExpression(
          doc, BAD_CAST "/TaintChecker/TaintDestinations/TaintDestination",
          &TaintParser::parseDestinations))
    return Errors::GeneralError;

  if (!executeXpathExpression(doc,
                              BAD_CAST "/TaintChecker/TaintFilters/TaintFilter",
                              &TaintParser::parseFilters))
    return Errors::GeneralError;

  // Cleanup
  xmlCleanupParser();
  xmlFreeDoc(doc);
  return 0;
}

bool TaintParser::executeXpathExpression(xmlDocPtr doc,
                                         const xmlChar *xpathExpr,
                                         ResultManager ResultManagerFunction) {
  xmlXPathContextPtr xpathCtx;
  xmlXPathObjectPtr xpathObj;

  assert(doc);
  assert(xpathExpr);

  // Create xpath evaluation context.
  xpathCtx = xmlXPathNewContext(doc);
  if (xpathCtx == NULL) {
    xmlFreeDoc(doc);
    return false;
  }

  // Evaluate xpath expression.
  xpathObj = xmlXPathEvalExpression(xpathExpr, xpathCtx);
  if (xpathObj == NULL) {
    xmlXPathFreeContext(xpathCtx);
    xmlFreeDoc(doc);
    return false;
  }

  (this->*ResultManagerFunction)(xpathObj->nodesetval);

  /* Cleanup */
  xmlXPathFreeObject(xpathObj);
  xmlXPathFreeContext(xpathCtx);
  return true;
}

void TaintParser::parseSources(xmlNodeSetPtr nodes) {
  xmlNodePtr cur;
  int size;

  size = (nodes) ? nodes->nodeNr : 0;
  for (int i = 0; i < size; ++i) {
    assert(nodes->nodeTab[i]);

    if (nodes->nodeTab[i]->type == XML_ELEMENT_NODE) {
      cur = nodes->nodeTab[i];
      Source source = Source();
      source.setCalleeType("all");

      xmlNodePtr node = cur->children;
      while (node != cur->last) {
        if (xmlStrEqual(node->name, xmlCharStrdup("method"))) {
          std::string generateMethod =
              std::string(reinterpret_cast<char *>(node->children->content));
          source.setName(generateMethod);
        }
        if (xmlStrEqual(node->name, xmlCharStrdup("calleetype"))) {
          std::string calleeType =
          std::string(reinterpret_cast<char *>(node->children->content));
          source.setCalleeType(calleeType);
        }
        if (xmlStrEqual(node->name, xmlCharStrdup("params"))) {
          xmlNodePtr paramsNodes = node->children;
          while (paramsNodes != node->last) {
            if (xmlStrEqual(paramsNodes->name, xmlCharStrdup("value"))) {
              source.addArgument(std::stoi(
                  reinterpret_cast<char *>(paramsNodes->children->content)));
            }
            paramsNodes = paramsNodes->next;
          }
        }
        node = node->next;
      }
      sourceList.push_back(source);
    } else {
      cur = nodes->nodeTab[i];
    }
  }
}

void TaintParser::parsePropagationRules(xmlNodeSetPtr nodes) {
  xmlNodePtr cur;
  int size;

  size = (nodes) ? nodes->nodeNr : 0;
  for (int i = 0; i < size; ++i) {
    assert(nodes->nodeTab[i]);

    if (nodes->nodeTab[i]->type == XML_ELEMENT_NODE) {
      cur = nodes->nodeTab[i];
      Propagator propagator = Propagator();
      propagator.setCalleeType("all");

      xmlNodePtr node = cur->children;
      while (node != cur->last) {
        if (xmlStrEqual(node->name, xmlCharStrdup("method"))) {
          std::string propagateMethod =
              std::string(reinterpret_cast<char *>(node->children->content));
          propagator.setName(propagateMethod);
        }
        if (xmlStrEqual(node->name, xmlCharStrdup("calleetype"))) {
          std::string calleeType =
          std::string(reinterpret_cast<char *>(node->children->content));
          propagator.setCalleeType(calleeType);
        }
        if (xmlStrEqual(node->name, xmlCharStrdup("sources"))) {
          xmlNodePtr paramsNodes = node->children;
          while (paramsNodes != node->last) {
            if (xmlStrEqual(paramsNodes->name, xmlCharStrdup("value"))) {
              propagator.addSourceArg(std::stoi(
                  reinterpret_cast<char *>(paramsNodes->children->content)));
            }
            paramsNodes = paramsNodes->next;
          }
        }
        if (xmlStrEqual(node->name, xmlCharStrdup("destinations"))) {
          xmlNodePtr paramsNodes = node->children;
          while (paramsNodes != node->last) {
            if (xmlStrEqual(paramsNodes->name, xmlCharStrdup("value"))) {
              propagator.addDestArg(std::stoi(
                  reinterpret_cast<char *>(paramsNodes->children->content)));
            }
            paramsNodes = paramsNodes->next;
          }
        }
        node = node->next;
      }
      propagationRuleList.push_back(propagator);
    } else {
      cur = nodes->nodeTab[i];
    }
  }
}

void TaintParser::parseDestinations(xmlNodeSetPtr nodes) {
  xmlNodePtr cur;
  int size;

  size = (nodes) ? nodes->nodeNr : 0;
  for (int i = 0; i < size; ++i) {
    assert(nodes->nodeTab[i]);

    if (nodes->nodeTab[i]->type == XML_ELEMENT_NODE) {
      cur = nodes->nodeTab[i];
      Sink sink = Sink();
      sink.setCalleeType("all");

      xmlNodePtr node = cur->children;
      while (node != cur->last) {
        if (xmlStrEqual(node->name, xmlCharStrdup("method"))) {
          std::string destinationMethod =
              std::string(reinterpret_cast<char *>(node->children->content));
          sink.setName(destinationMethod);
        }
        if (xmlStrEqual(node->name, xmlCharStrdup("calleetype"))) {
          std::string calleeType =
          std::string(reinterpret_cast<char *>(node->children->content));
          sink.setCalleeType(calleeType);
        }
        if (xmlStrEqual(node->name, xmlCharStrdup("params"))) {
          xmlNodePtr paramsNodes = node->children;
          while (paramsNodes != node->last) {
            if (xmlStrEqual(paramsNodes->name, xmlCharStrdup("value"))) {
              sink.addArgument(std::stoi(
                  reinterpret_cast<char *>(paramsNodes->children->content)));
            }
            paramsNodes = paramsNodes->next;
          }
        }
        node = node->next;
      }
      destinationList.push_back(sink);
    } else {
      cur = nodes->nodeTab[i];
    }
  }
}

void TaintParser::parseFilters(xmlNodeSetPtr nodes) {
  xmlNodePtr cur;
  int size;

  size = (nodes) ? nodes->nodeNr : 0;
  for (int i = 0; i < size; ++i) {
    assert(nodes->nodeTab[i]);

    if (nodes->nodeTab[i]->type == XML_ELEMENT_NODE) {
      cur = nodes->nodeTab[i];
      Filter filter = Filter();
      filter.setCalleeType("all");

      xmlNodePtr node = cur->children;
      while (node != cur->last) {
        if (xmlStrEqual(node->name, xmlCharStrdup("method"))) {
          std::string filterMethod =
              std::string(reinterpret_cast<char *>(node->children->content));
          filter.setName(filterMethod);
        }
        if (xmlStrEqual(node->name, xmlCharStrdup("calleetype"))) {
          std::string calleeType =
          std::string(reinterpret_cast<char *>(node->children->content));
          filter.setCalleeType(calleeType);
        }
        if (xmlStrEqual(node->name, xmlCharStrdup("params"))) {
          xmlNodePtr paramsNodes = node->children;
          while (paramsNodes != node->last) {
            if (xmlStrEqual(paramsNodes->name, xmlCharStrdup("value"))) {
              filter.addArgument(std::stoi(
                  reinterpret_cast<char *>(paramsNodes->children->content)));
            }
            paramsNodes = paramsNodes->next;
          }
        }
        node = node->next;
      }
      filterList.push_back(filter);
    } else {
      cur = nodes->nodeTab[i];
    }
  }
}

bool TaintParser::validateXMLAgaintSchema(xmlDocPtr doc) {
  xmlSchemaParserCtxtPtr ctxt;
  xmlSchemaPtr schema;
  xmlSchemaValidCtxtPtr validCtxt;

  assert(doc);

  ctxt = xmlSchemaNewParserCtxt(this->XSDfilename.data());

  if (ctxt != NULL) {
    schema = xmlSchemaParse(ctxt);
    xmlSchemaFreeParserCtxt(ctxt);

    validCtxt = xmlSchemaNewValidCtxt(schema);
    int ret = xmlSchemaValidateDoc(validCtxt, doc);
    if (ret == 0) {
      return true;
    } else {
      return false;
    }
  }
  return false;
}

SourceList TaintParser::getSourceList() { return sourceList; }

PropagationList TaintParser::getPropagationRuleList() {
  return propagationRuleList;
}

DestinationList TaintParser::getDestinationList() { return destinationList; }

FilterList TaintParser::getFilterList() { return filterList; }

std::string TaintParser::toString() {
  std::string str = "Paser {\n";
  str = str + "Sources :\n";
  for (SourceList::const_iterator I = sourceList.begin(), E = sourceList.end();
       I != E; ++I) {
    Source source = *I;
    str += " - " + source.toString() + "\n";
  }

  str = str + "Propagators: \n";
  for (PropagationList::const_iterator I = propagationRuleList.begin(),
                                        E = propagationRuleList.end();
       I != E; ++I) {
    Propagator propagator = *I;
    str += " - " + propagator.toString() + "\n";
  }

  str = str + "Sinks: \n";
  for (DestinationList::const_iterator I = destinationList.begin(),
                                        E = destinationList.end();
       I != E; ++I) {
    Sink sink = *I;
    str += " - " + sink.toString() + "\n";
  }

  str = str + "Filters:\n";
  for (FilterList::const_iterator I = filterList.begin(), E = filterList.end();
       I != E; ++I) {
    Filter filter = *I;
    str += " - " + filter.toString() + "\n";
  }
  str = str + "}\n";
  return str;
}
}
