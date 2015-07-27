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

#include "includes/TaintVisitor.h"

namespace taintutil {

  // --------------------------------- //
  //    TaintVisitor implementation    //
  // --------------------------------- //
  
  void
  TaintVisitor::Execute(Stmt* Stmt){
    for (Stmt::child_iterator I = Stmt->child_begin(), E = Stmt->child_end();
         I!=E; ++I){
      if (*I){
        Visit(*I);
      }
    }
  }
  
  void
  TaintVisitor::VisitDeclStmt(DeclStmt* declStmt){}
  
  void
  TaintVisitor::VisitCallExpr(CallExpr *CE){
    for (unsigned int i = 0; i < CE->getNumArgs(); ++i) {
      Expr *arg = CE->getArg(i);
      if (CastExpr *castExpr = dyn_cast<CastExpr>(arg)){
        arg = castExpr->getSubExprAsWritten();
      }
      if (IsMemberExpr(arg))
        // The arg is a member expression, it has to be marked as tainted.
        MarkTaint(arg);
    }
  }
  
  void
  TaintVisitor::VisitCXXMemberCallExpr(CallExpr *CE){
    for (unsigned int i = 0; i < CE->getNumArgs(); ++i) {
      Expr *arg = CE->getArg(i);
      if (CastExpr *castExpr = dyn_cast<CastExpr>(arg)){
        arg = castExpr->getSubExprAsWritten();
      }
      if (IsMemberExpr(arg))
        // The arg is a member expression, it has to be marked as tainted.
        MarkTaint(arg);
    }
    Visit(CE->getDirectCallee()->getBody());
  }
  
  void
  TaintVisitor::VisitBinAssign(BinaryOperator *BO){
    if (BO->isAssignmentOp()){
      // We get the left hand part of the assignment.
      Expr *lhs = BO->getLHS();
      if (IsMemberExpr(lhs) || HasGlobalStorage(lhs))
        MarkTaint(lhs);
    }
  }
  
  // Private methods.
  bool
  TaintVisitor::HasGlobalStorage(Expr* expr){
    if (DeclRefExpr *declRefExpr = dyn_cast<DeclRefExpr>(expr)){
      NamedDecl *namedDecl = declRefExpr->getFoundDecl();
      if(VarDecl *varDecl = dyn_cast<VarDecl>(namedDecl)){
        if (varDecl->hasGlobalStorage())
          return true;
      }
    }
    return false;
  }
  
  bool
  TaintVisitor::IsMemberExpr(Expr* Expr){
    // See if we have to consider something else.
    if (isa<MemberExpr>(Expr))
      return true;
    return false;
  }
};