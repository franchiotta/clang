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

#include "clang/AST/StmtVisitor.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace taintutil {
  
  
  ///
  /// TODO: describre the purpose of this class.
  ///
	class TaintVisitor : public StmtVisitor<TaintVisitor> {
  protected:
    CheckerContext C;
    ProgramStateRef State;
  public:
    TaintVisitor(CheckerContext &C, ProgramStateRef State): C(C), State(State){}
    virtual ~TaintVisitor(){}
    
    //void VisitStmt(Stmt* stmt);
    void VisitDeclStmt(DeclStmt* DeclStmt);
    
    // Check if a member variable was passed to the call. If that is the case,
    // mark it as tainted.
    void VisitCallExpr(CallExpr *CE);
    
    // The same as VisitCallExpr, but it goes further. Since is a member call, we
    // continue visiting the invoked method.
    void VisitCXXMemberCallExpr(CallExpr *CE);
    
    // If an assignment is found, get the left hand side part(lhs) and check if it
    //is a member expression. If it is, mark as tainted.
    void VisitBinAssign(BinaryOperator *BO);

    void Execute(Stmt *S);

  private:
    // Tries to get the symbol associated with the symbolic expression, and mark
    // it as tainted.
    virtual void MarkTaint(Expr* Stmt) = 0;

    // Indicates if the expression referes to a member variable.
    bool IsMemberExpr(Expr* expr);
    
    // Indicates if the expression refers to a variable that has global storage.
    bool HasGlobalStorage(Expr* expr);
  };
};

