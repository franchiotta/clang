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

#include "clang/AST/ExprCXX.h"
#include "clang/AST/DeclCXX.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace taintutil {

/// Is this funcion declaration applicable based on its kind?
bool isFDApplicable(const FunctionDecl *FD);

/// \brief Given a pointer argument, get the symbol of the value it contains
/// (points to).
SymbolRef getPointedToSymbol(CheckerContext &C, const Expr *Arg);

SymbolRef getSymbol(SVal Val);

bool isMemberExpr(Expr *Expr);

bool hasGlobalStorage(Expr *Expr);

std::string exprToString(const Expr *E);

void displayWelcome(std::string ConfigFileName, std::string DebugFileName);

std::string replaceMessage(const char *MsgTemplate, const char *MsgToComplete);

std::string getCallExpCalleeType(const CallExpr *CE, CheckerContext &C);

template <typename... Args>
void debug(FILE *DebugFile, const char *Format, Args... Arguments) {
  if (DebugFile)
    fprintf(DebugFile, Format, Arguments...);
}

class TaintBugVisitor : public BugReporterVisitorImpl<TaintBugVisitor> {
protected:
  SymbolRef Symbol;
  const Expr *Expression;

  // If true, the visitor will look up the node in which the Symbol got
  // tainted. Otherwise, it will look up for the node in which the expression
  // got tainted instead (this is the way the checker marked as tainted return
  // values).
  bool SymbolLookup;

public:
  TaintBugVisitor(SymbolRef Symbol, const Expr *Expression, bool SymbolLookup)
      : Symbol(Symbol), Expression(Expression), SymbolLookup(SymbolLookup) {}

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

//
// Class used to hold call information between callbacks. Currently, it is being
// used to share the callee type between checkPreStmt and CheckBin callbacks.
//
class CallInfo {
public:
  std::string Name;
  std::string CalleeType;

  CallInfo(std::string Name, std::string CalleeType)
      : Name(Name), CalleeType(CalleeType) {}

  inline bool operator==(const CallInfo &That) const {
    return (this->Name == That.Name && this->CalleeType == That.CalleeType);
  }
  
  inline bool operator<(const CallInfo &That) const {
    return this->Name < That.Name;
  }
  
  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddString(Name);
    ID.AddString(CalleeType);
  }
};

//
// Class used to hold taint information between pre and post checks callbacks.
// It contains the arguments to the call to be tainted or filtered.
//
class TaintInfo {
public:
  enum class Operation { TAINT, UNTAINT };
  
private:
  int Id; // Used just for the profile.
  std::string Name;
  enum Operation Op;
  SmallVector<unsigned, 2> Arguments;

public:
  TaintInfo() {}
  
  TaintInfo(std::string Name, enum Operation Op) : Name(Name), Op(Op) {
    Arguments = SmallVector<unsigned, 2>();
  }

  TaintInfo(std::string Name, enum Operation Op, SmallVector<unsigned, 2> Args)
  : Name(Name), Op(Op), Arguments(Args){}
  
  inline bool operator==(const TaintInfo &That) const {
    return this->Name == That.Name  && this->Op == That.Op;
  }

  inline bool operator<(const TaintInfo &That) const {
    return this->Name < That.Name;
  }

  std::string getName() const {return Name;}
  
  enum Operation getOperation() const {return Op;}
  
  SmallVector<unsigned, 2> getArguments() const {return Arguments;}
  
  void addArgument(unsigned Argument) { Arguments.push_back(Argument); }
  
  bool empty() const { return Arguments.empty(); }
  
  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddString(Name);
    ID.AddPointer(&Id);
  }
};
};
