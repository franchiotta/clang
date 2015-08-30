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
/// This file contains utility declaration for the use of CustomTaintChecker
///
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace taintutil {

/// Is this funcion declaration applicable based on its kind?
bool isFDApplicable(const FunctionDecl *FD);

/// \brief Given a pointer argument, get the symbol of the value it contains
/// (points to).
SymbolRef getPointedToSymbol(CheckerContext &C, const Expr *Arg);
  
bool isMemberExpr(Expr *Expr);

bool hasGlobalStorage(Expr *Expr);

std::string exprToString(const Expr *E);

void displayWelcome(std::string ConfigFileName, std::string DebugFileName);

std::string replaceMessage(const char *MsgTemplate, const char *MsgToComplete);

template <typename... Args>
void debug(FILE *DebugFile, const char *Format, Args... Arguments) {
  if (DebugFile)
    fprintf(DebugFile, Format, Arguments...);
}

class TaintBugVisitor : public BugReporterVisitorImpl<TaintBugVisitor> {
protected:
  SymbolRef Symbol;
  std::string StrExpr;

public:
  TaintBugVisitor(SymbolRef symbol, std::string strExpr)
      : Symbol(symbol), StrExpr(strExpr) {}

  void Profile(llvm::FoldingSetNodeID &ID) const override {
    static int X = 0;
    ID.AddPointer(&X);
    ID.AddPointer(Symbol);
  }
  
  PathDiagnosticPiece *VisitNode(const ExplodedNode *N,
                                 const ExplodedNode *PrevN,
                                 BugReporterContext &BRC,
                                 BugReport &BR) override;
};
};
