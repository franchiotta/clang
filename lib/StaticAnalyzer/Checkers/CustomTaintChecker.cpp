//== CustomTaintChecker.cpp ----------------------------------- -*- C++ -*--=//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This checker defines the attack surface for generic taint propagation.
//
// The taint information produced by it might be useful to other checkers. For
// example, checkers should report errors which involve tainted data more
// aggressively, even if the involved symbols are under constrained.
//
// This checker is based on GenericTaintChecker, but it adds custom
// configuration to the checker from a xml resource.
//
//===----------------------------------------------------------------------===//

#include "includes/TaintParser.h"
#include "includes/TaintPropagation.h"
#include "includes/TaintUtil.h"

#include "clang/AST/Attr.h"
#include "ClangSACheckers.h"
#include "clang/Config/config.h"
#include "clang/Basic/Builtins.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/TaintTag.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "llvm/Support/raw_ostream.h"

#include <climits>
#include <utility>

#ifdef CLANG_HAVE_LIBXML
#include <libxml/xpath.h>
#include <libxml/parser.h>
#include <libxml/xmlschemastypes.h>
#endif

using namespace clang;
using namespace ento;
using namespace taintutil;
namespace {

// File used to write debug information (its path is passed by the user as a
// parameter to the checker).
static FILE *DebugFile;

// Location of configuration schema used to validate the configuration file
// entered by the user.
static const std::string ConfigSchema =
    std::string(CLANG_SCHEMA_DIR + (std::string) "/taint-rules.xsd");

class CustomTaintChecker
    : public Checker<check::PostStmt<CallExpr>, check::PreStmt<CallExpr>,
                     check::Bind> {
public:
  CustomTaintChecker() {}

  ~CustomTaintChecker() {
    if (DebugFile)
      fclose(DebugFile);
  }

  static void *getTag() {
    static int Tag;
    return &Tag;
  }

  /// \brief Initialization class.
  void initialization(std::string ConfigurationFilePath,
                      std::string DebugFilePath);

  void checkPostStmt(const CallExpr *CE, CheckerContext &C) const;

  void checkPreStmt(const CallExpr *CE, CheckerContext &C) const;

  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &) const;

private:
  mutable std::unique_ptr<BugType> UseTaintedBugType;
  inline void initBugType() const {
    if (!UseTaintedBugType)
      UseTaintedBugType.reset(
          new BugType(this, "Use of Untrusted Data", "Untrusted Data"));
  }

  /// \brief Catch taint related bugs. Check if tainted data is passed to a
  /// system call etc.
  bool checkPre(const CallExpr *CE, CheckerContext &C) const;

  /// \brief Check if the method is a generator. If so, it is marked as a
  /// variable to be tainted on post-visit.
  void checkGenerators(const CallExpr *CE, CheckerContext &C) const;

  bool checkCustomDestination(const CallExpr *CE, StringRef Name,
                              CheckerContext &C) const;

  /// \brief Check if the method is a filter. If so, it is marked as a variable
  /// to be untainted on post-visit.
  void checkFilters(const CallExpr *CE, CheckerContext &C) const;

  /// \brief Add taint sources on a pre-visit.
  void addSourcesPre(const CallExpr *CE, CheckerContext &C) const;

  /// \brief Clear Call Info stored at pre-visit if there is any.
  void clearCallInfo(const CallExpr *CE, CheckerContext &C) const;

  /// \brief Remove call information from UpperCallInfo registered set.
  ProgramStateRef removeCallInfo(ProgramStateRef State,
                                 std::string CallName) const;

  /// \brief Propagate taint generated at pre-visit.
  bool propagateFromPre(const CallExpr *CE, CheckerContext &C) const;

  /// \brief If the method was marked as filter at pre-visit, untaint
  /// the arguments specified by it.
  bool propagateFilterFromPre(const CallExpr *CE, CheckerContext &C) const;

  /// \brief Add taint sources on a post visit.
  bool addSourcesPost(const CallExpr *CE, CheckerContext &C) const;

  /// \brief taints member or global variables in the left hand side of an
  /// assignment.
  ProgramStateRef taintMemberAndGlobalVars(SVal Val, const Stmt *S,
                                           ProgramStateRef State) const;

  /// Check if the region the expression evaluates to is the standard input,
  /// and thus, is tainted.
  static bool isStdin(const Expr *E, CheckerContext &C);

  /// Functions defining the attack surface.
  typedef ProgramStateRef (CustomTaintChecker::*FnCheck)(
      const CallExpr *, CheckerContext &C) const;

  ProgramStateRef postScanf(const CallExpr *CE, CheckerContext &C) const;

  ProgramStateRef postSocket(const CallExpr *CE, CheckerContext &C) const;

  ProgramStateRef postRetTaint(const CallExpr *CE, CheckerContext &C) const;

  /// Taint the scanned input if the file is tainted.
  ProgramStateRef preFscanf(const CallExpr *CE, CheckerContext &C) const;

  /// Check for CWE-134: Uncontrolled Format String.
  static const char MsgUncontrolledFormatString[];

  bool checkUncontrolledFormatString(const CallExpr *CE,
                                     CheckerContext &C) const;

  static const char MsgSanitizeArgs[];

  /// Check for:
  /// CERT/STR02-C. "Sanitize data passed to complex subsystems"
  /// CWE-78, "Failure to Sanitize Data into an OS Command"
  static const char MsgSanitizeSystemArgs[];

  bool checkSystemCall(const CallExpr *CE, StringRef Name,
                       CheckerContext &C) const;

  /// Check if tainted data is used as a buffer size ins strn.. functions,
  /// and allocators.
  static const char MsgTaintedBufferSize[];

  bool checkTaintedBufferSize(const CallExpr *CE, const FunctionDecl *FDecl,
                              CheckerContext &C) const;

  /// Generate a report if the expression is tainted or points to tainted data.
  bool generateReportIfTainted(const Expr *E, const char Msg[],
                               CheckerContext &C) const;

  /// Set configuration to checker from taint parser.
  void setConfiguration(TaintParser TP) const;

  class TaintPropagationRule : public TaintPropagation {
  public:
    TaintPropagationRule() : TaintPropagation() {}

    TaintPropagationRule(unsigned SArg, unsigned DArg, bool TaintRet = false)
        : TaintPropagation(SArg, DArg, TaintRet) {}

    TaintPropagationRule(unsigned SArg1, unsigned SArg2, unsigned DArg,
                         bool TaintRet = false)
        : TaintPropagation(SArg1, SArg2, DArg, TaintRet) {}

    ProgramStateRef process(const CallExpr *CE, CheckerContext &C) const;

  private:
    static inline bool isTaintedOrPointsToTainted(const Expr *E,
                                                  ProgramStateRef State,
                                                  CheckerContext &C);
  };

  bool isSourceExpression(StringRef Name, StringRef CalleeType) const;

  Source *getSourceExpression(StringRef Name, StringRef CalleeType) const;

  TaintPropagationRule getPropagatorExpression(StringRef Name,
                                               StringRef CalleeType) const;

  Sink *getDestinationExpression(StringRef Name, StringRef CalleeType) const;

  Filter *getFilterExpression(StringRef Name, StringRef CalleeType) const;

  TaintInfo *getTaintInfo(ProgramStateRef State, std::string Name,
                         enum TaintInfo::Operation Op) const;

  CallInfo *getCallInfo(ProgramStateRef State, std::string Name) const;

  bool EmitReportTaintedOnDestination(const Expr *Expr, const char Msg[],
                                      CheckerContext &C,
                                      SymbolRef Symbol) const;

  /// Get the propagation rule for a given function.
  TaintPropagationRule getTaintPropagationRule(const FunctionDecl *FDecl,
                                               StringRef Name,
                                               StringRef CalleType,
                                               CheckerContext &C) const;

  //
  // Variables for holding information retrieved from xml configuration files.
  //
  // This checker defines four kind of functions:
  // - Generators (or sources): methods that can introduce taint data to
  // variables (or to object in which the functions are applied to).
  // - Propagations: methods that can propagate taint data to other variables.
  // - Destinations (or sinks): methods that can have dangerous behaviour if
  // taint data is passed on.
  // - Filters (or sanitizers): methods that sanitize taint variables.
  //

  ///
  /// \brief Defines a list of Sources, which is an association between
  /// generator function names, and its sources arguments.
  ///
  static SourceList SourceList;

  ///
  /// \brief Defines a list of propagators, which is an association between
  /// propagation function names, and its source arguments, and destination
  /// arguments.
  ///
  static PropagationList PropagationRuleList;

  ///
  /// \brief Defines a list of Sinks, which is an association between
  /// destination function names, and its taget arguments.
  ///
  static DestinationList DestinationList;

  ///
  /// \brief Defines a list of Filters, which is an association between
  /// sanitizers function names, and its filter arguments.
  ///
  static FilterList FilterList;

}; // End of CustomTaintChecker

SourceList CustomTaintChecker::SourceList = taintutil::SourceList();

PropagationList CustomTaintChecker::PropagationRuleList =
    taintutil::PropagationList();

DestinationList CustomTaintChecker::DestinationList =
    taintutil::DestinationList();

FilterList CustomTaintChecker::FilterList = taintutil::FilterList();

const char CustomTaintChecker::MsgUncontrolledFormatString[] =
    "Untrusted data is used as a format string "
    "(CWE-134: Uncontrolled Format String)";

const char CustomTaintChecker::MsgSanitizeArgs[] =
    "Untrusted data '%s' is passed to this sink. "
    "No filter found since it got tainted, make sure to sanitize before "
    "passing to it.";

const char CustomTaintChecker::MsgSanitizeSystemArgs[] =
    "Untrusted data is passed to a system call "
    "(CERT/STR02-C. Sanitize data passed to complex subsystems)";

const char CustomTaintChecker::MsgTaintedBufferSize[] =
    "Untrusted data is used to specify the buffer size "
    "(CERT/STR31-C. Guarantee that storage for strings has sufficient space "
    "for "
    "character data and the null terminator)";

} // End of anonymous namespace

/// Set which is used to pass information from call pre-visit instruction
/// to the call post-visit. The values are TaintInfo objects, whose fields are
/// the name of the call and a list of unsigned integers, which are either
/// ReturnValueIndex, or indexes of the pointer/reference argument, which
/// points to data, which should be tainted on return.
REGISTER_SET_WITH_PROGRAMSTATE(TaintArgsOnPostVisit, TaintInfo)
// The UpperCallInfo set is mainly used to pass the CalleeType from the
// CheckPreStmt to checkBind callback.
REGISTER_SET_WITH_PROGRAMSTATE(UpperCallInfo, CallInfo)

CustomTaintChecker::TaintPropagationRule
CustomTaintChecker::getTaintPropagationRule(const FunctionDecl *FDecl,
                                            StringRef Name, StringRef CalleType,
                                            CheckerContext &C) const {
  // TODO: Currently, we might lose precision here: we always mark a return
  // value as tainted even if it's just a pointer, pointing to tainted data.

  // Check for exact name match for functions without builtin substitutes.
  TaintPropagationRule Rule =
      llvm::StringSwitch<TaintPropagationRule>(Name)
          .Case("atoi", TaintPropagationRule(0, ReturnValueIndex))
          .Case("atol", TaintPropagationRule(0, ReturnValueIndex))
          .Case("atoll", TaintPropagationRule(0, ReturnValueIndex))
          .Case("getc", TaintPropagationRule(0, ReturnValueIndex))
          .Case("fgetc", TaintPropagationRule(0, ReturnValueIndex))
          .Case("getc_unlocked", TaintPropagationRule(0, ReturnValueIndex))
          .Case("getw", TaintPropagationRule(0, ReturnValueIndex))
          .Case("toupper", TaintPropagationRule(0, ReturnValueIndex))
          .Case("tolower", TaintPropagationRule(0, ReturnValueIndex))
          .Case("strchr", TaintPropagationRule(0, ReturnValueIndex))
          .Case("strrchr", TaintPropagationRule(0, ReturnValueIndex))
          .Case("read", TaintPropagationRule(0, 2, 1, true))
          .Case("pread", TaintPropagationRule(InvalidArgIndex, 1, true))
          .Case("gets", TaintPropagationRule(InvalidArgIndex, 0, true))
          .Case("fgets", TaintPropagationRule(2, 0, true))
          .Case("getline", TaintPropagationRule(2, 0))
          .Case("getdelim", TaintPropagationRule(3, 0))
          .Case("fgetln", TaintPropagationRule(0, ReturnValueIndex))
          .Default(TaintPropagationRule());

  if (Rule.isNull()) {
    // If the previous case did not find a Propagation Rule for the method, now
    // it has to check the custom rules defined by the user.
    Rule = getPropagatorExpression(Name, CalleType);
  }
  if (!Rule.isNull())
    return Rule;

  // Check if it's one of the memory setting/copying functions.
  // This check is specialized but faster then calling isCLibraryFunction.
  unsigned BId = 0;
  if ((BId = FDecl->getMemoryFunctionKind()))
    switch (BId) {
    case Builtin::BImemcpy:
    case Builtin::BImemmove:
    case Builtin::BIstrncpy:
    case Builtin::BIstrncat:
      return TaintPropagationRule(1, 2, 0, true);
    case Builtin::BIstrlcpy:
    case Builtin::BIstrlcat:
      return TaintPropagationRule(1, 2, 0, false);
    case Builtin::BIstrndup:
      return TaintPropagationRule(0, 1, ReturnValueIndex);

    default:
      break;
    };

  // Process all other functions which could be defined as builtins.
  if (Rule.isNull()) {
    if (C.isCLibraryFunction(FDecl, "snprintf") ||
        C.isCLibraryFunction(FDecl, "sprintf"))
      return TaintPropagationRule(InvalidArgIndex, 0, true);
    else if (C.isCLibraryFunction(FDecl, "strcpy") ||
             C.isCLibraryFunction(FDecl, "stpcpy") ||
             C.isCLibraryFunction(FDecl, "strcat"))
      return TaintPropagationRule(1, 0, true);
    else if (C.isCLibraryFunction(FDecl, "bcopy"))
      return TaintPropagationRule(0, 2, 1, false);
    else if (C.isCLibraryFunction(FDecl, "strdup") ||
             C.isCLibraryFunction(FDecl, "strdupa"))
      return TaintPropagationRule(0, ReturnValueIndex);
    else if (C.isCLibraryFunction(FDecl, "wcsdup"))
      return TaintPropagationRule(0, ReturnValueIndex);
  }

  // Skipping the following functions, since they might be used for cleansing
  // or smart memory copy:
  // - memccpy - copying until hitting a special character.

  return TaintPropagationRule();
}

// ---------------------------------------- //
//     CustomTaintChecker implementation    //
// ---------------------------------------- //

void CustomTaintChecker::initialization(std::string ConfigurationFilePath,
                                        std::string DebugFilePath) {

  DebugFile = fopen(DebugFilePath.data(), "a");
  displayWelcome(ConfigurationFilePath, DebugFilePath);
  debug(DebugFile, "\n------Starting checker------\n");

#if defined CLANG_HAVE_LIBXML
  TaintParser parser = TaintParser(ConfigurationFilePath, ConfigSchema);

  int result;
  if ((result = parser.process()) == 0) {
    // Getting taint configuration data from TaintParser object.
    setConfiguration(parser);
    debug(DebugFile, parser.toString().data());
  } else {
    // An error occurred trying to parse configuration file.
    switch (result) {
    case parser.Errors::ValidationError:
      llvm::outs() << "Configuration file does not validate against schema.\n";
      break;
    default:
      llvm::outs() << "An error occurred trying to load configuration file.\n";
      break;
    }
    llvm::outs() << "Loading just default configuration.\n\n";
  }
#else
  debug(DebugFile, "No LIBXML library found. Using default setting. \n");
#endif
}

void CustomTaintChecker::checkPreStmt(const CallExpr *CE,
                                      CheckerContext &C) const {
  // Check for errors first.
  if (checkPre(CE, C))
    return;

  // Check if a custom generator is applied.
  checkGenerators(CE, C);

  // Check if a custom filter is applied.
  checkFilters(CE, C);

  // Add taint second.
  addSourcesPre(CE, C);
}

void CustomTaintChecker::checkPostStmt(const CallExpr *CE,
                                       CheckerContext &C) const {
  if (propagateFromPre(CE, C))
    return;
  if (propagateFilterFromPre(CE, C))
    return;
  if (addSourcesPost(CE, C))
    return;

  // If none of the previous methods added a new transition, clear the call info
  // from the State (Note: if they did add a transition, it means that they
  // already cleared it).
  clearCallInfo(CE, C);
}

void CustomTaintChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                   CheckerContext &C) const {
  const Decl *D = C.getCurrentAnalysisDeclContext()->getDecl();
  if (!D)
    return;

  // It only continues for FunctionDecl.
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  StringRef Name = FD->getNameInfo().getName().getAsString();
  ProgramStateRef State = C.getState();
  // Verify if the checkPreStmt for the upper ExprCall stored any call
  // information.
  const CallInfo *CallInfo = getCallInfo(State, Name);
  if (!CallInfo)
    return;

  // If the FunctionDecl name is a valid source expression, it continues.
  // Otherwise, it ends.
  if (!isSourceExpression(Name, CallInfo->CalleeType)) {
    delete CallInfo;
    return;
  }

  // If the statement 'S' is an assignment, taint the left hand side if it is a
  // member or global variable.
  State = taintMemberAndGlobalVars(Val, S, State);

  if (State != C.getState()) {
    C.addTransition(State);
  }
  delete CallInfo;
}

bool CustomTaintChecker::checkPre(const CallExpr *CE, CheckerContext &C) const {

  // If there is a format argument, it checks if the arg is tainted.
  if (checkUncontrolledFormatString(CE, C))
    return true;

  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  StringRef Name = C.getCalleeName(FDecl);

  if (!isFDApplicable(FDecl))
    return true;

  if (Name.empty())
    return true;

  if (checkCustomDestination(CE, Name, C))
    return true;

  // If the call is a system call. Checks for an specific argument for tainting.
  if (checkSystemCall(CE, Name, C))
    return true;

  // If the call has a buffer size argument. Checks it for tainting.
  if (checkTaintedBufferSize(CE, FDecl, C))
    return true;

  return false;
}

void CustomTaintChecker::checkGenerators(const CallExpr *CE,
                                         CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  StringRef Name = C.getCalleeName(FDecl);
  StringRef CalleeType = getCallExpCalleeType(CE, C);
  if (Source *Source = getSourceExpression(Name, CalleeType)) {
    // This set is used to communicate checPreStmt with checkBind callbacks.
    // Here we are storing the call information such as its Name and its Callee
    // type, so we can have that knowledge in checkBind.
    State = State->add<UpperCallInfo>(CallInfo(Name, CalleeType));

    TaintInfo TI = TaintInfo(Name, TaintInfo::Operation::TAINT);
    for (ArgVector::const_iterator J = Source->getArgs().begin(),
                                   Z = Source->getArgs().end();
         J != Z; ++J) {

      unsigned ArgNum = *J;

      // Should we mark all arguments as tainted?
      if (ArgNum == InvalidArgIndex) {
        // For all pointer and references that were passed in:
        // If they are not pointing to const data, mark data as tainted.
        // TODO: So far we are just going one level down; ideally we'd need to
        // recurse here.
        for (unsigned int i = 0; i < CE->getNumArgs(); ++i) {
          const Expr *Arg = CE->getArg(i);
          // Process pointer argument.
          const Type *ArgTy = Arg->getType().getTypePtr();
          QualType PType = ArgTy->getPointeeType();
          if ((!PType.isNull() && !PType.isConstQualified()) ||
              (ArgTy->isReferenceType() && !Arg->getType().isConstQualified()))
            TI.addArgument(i);
        }
        continue;
      }

      // Should mark the return value?
      if (ArgNum == ReturnValueIndex) {
        TI.addArgument(ReturnValueIndex);
        continue;
      }

      // assert(ArgNum >= 0 && ArgNum < CE->getNumArgs());
      if (ArgNum >= CE->getNumArgs())
        continue;

      // Mark the given argument.
      TI.addArgument(ArgNum);
    }
    if (!TI.empty())
      State = State->add<TaintArgsOnPostVisit>(TI);
    delete Source;
  }
  if (State != C.getState())
    C.addTransition(State);
}

bool CustomTaintChecker::checkCustomDestination(const CallExpr *CE,
                                                StringRef Name,
                                                CheckerContext &C) const {
  if (Sink *Sink =
          getDestinationExpression(Name, getCallExpCalleeType(CE, C))) {
    for (ArgVector::const_iterator I = Sink->getArgs().begin(),
                                   E = Sink->getArgs().end();
         I != E; ++I) {
      int ArgNum = *I;
      if (generateReportIfTainted(CE->getArg(ArgNum), MsgSanitizeArgs, C))
        return true;
    }
    delete Sink;
  }
  return false;
}

void CustomTaintChecker::checkFilters(const CallExpr *CE,
                                      CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  StringRef Name = C.getCalleeName(FDecl);

  if (Filter *Filter = getFilterExpression(Name, getCallExpCalleeType(CE, C))) {
    TaintInfo TI = TaintInfo(Name, TaintInfo::Operation::UNTAINT);
    for (ArgVector::const_iterator J = Filter->getArgs().begin(),
                                   Z = Filter->getArgs().end();
         J != Z; ++J) {
      unsigned ArgNum = *J;

      // assert(ArgNum >= 0 && ArgNum < CE->getNumArgs());
      if (ArgNum >= CE->getNumArgs())
        break;

      // Mark the given argument.
      TI.addArgument(ArgNum);
    }
    if (!TI.empty())
      State = State->add<TaintArgsOnPostVisit>(TI);
    delete Filter;
  }
  if (State != C.getState())
    C.addTransition(State);
}

void CustomTaintChecker::addSourcesPre(const CallExpr *CE,
                                       CheckerContext &C) const {
  ProgramStateRef State = nullptr;
  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  StringRef Name = C.getCalleeName(FDecl);
  StringRef CalleeType = getCallExpCalleeType(CE, C);

  // First, try generating a propagation rule for this function.
  TaintPropagationRule Rule =
      getTaintPropagationRule(FDecl, Name, CalleeType, C);
  if (!Rule.isNull()) {
    State = Rule.process(CE, C);
    if (!State)
      return;
    C.addTransition(State);
    return;
  }

  // Otherwise, check if we have custom pre-processing implemented.
  FnCheck evalFunction = llvm::StringSwitch<FnCheck>(Name)
                             .Case("fscanf", &CustomTaintChecker::preFscanf)
                             .Default(nullptr);
  // Check and evaluate the call.
  if (evalFunction)
    State = (this->*evalFunction)(CE, C);
  if (!State)
    return;
  C.addTransition(State);
}

void CustomTaintChecker::clearCallInfo(const CallExpr *CE,
                                       CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Getting call name.
  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  StringRef Name = C.getCalleeName(FDecl);

  State = removeCallInfo(State, Name);
  if (State != C.getState()) {
    C.addTransition(State, C.getPredecessor());
  }
}

ProgramStateRef CustomTaintChecker::removeCallInfo(ProgramStateRef State,
                                                   std::string CallName) const {
  UpperCallInfoTy CallInfoList = State->get<UpperCallInfo>();
  for (llvm::ImmutableSet<CallInfo>::iterator I = CallInfoList.begin(),
                                              E = CallInfoList.end();
       I != E; ++I) {
    CallInfo CI = *I;
    if (CI.Name == CallName) {
      return State->remove<UpperCallInfo>(CI);
    }
  }
  return State;
}

bool CustomTaintChecker::propagateFromPre(const CallExpr *CE,
                                          CheckerContext &C) const {

  ProgramStateRef State = C.getState();

  // Getting call name.
  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  StringRef Name = C.getCalleeName(FDecl);

  // Depending on what was tainted at pre-visit, we determined a set of
  // arguments which should be tainted after the function returns. These are
  // stored in the state as TaintArgsOnPostVisit set.
  const TaintInfo *TaintInfo =
      getTaintInfo(State, Name, TaintInfo::Operation::TAINT);
  if (!TaintInfo)
    return false;

  const ArgVector Arguments = TaintInfo->getArguments();
  for (ArgVector::const_iterator I = Arguments.begin(), E = Arguments.end();
       I != E; ++I) {
    unsigned ArgNum = *I;

    // Special handling for the tainted return value.
    if (ArgNum == ReturnValueIndex) {
      State = State->addTaint(CE, C.getLocationContext());
      continue;
    }

    // The arguments are pointer arguments. The data they are pointing at is
    // tainted after the call.
    if (CE->getNumArgs() < (ArgNum + 1))
      continue;

    const Expr *Arg = CE->getArg(ArgNum);
    SymbolRef Sym = getPointedToSymbol(C, Arg);
    if (Sym)
      State = State->addTaint(Sym);
  }
  // Clear up the taint info from the state.
  State = State->remove<TaintArgsOnPostVisit>(*TaintInfo);
  delete TaintInfo;
  if (State != C.getState()) {
    State = removeCallInfo(State, Name);
    C.addTransition(State);
    return true;
  }
  return false;
}

bool CustomTaintChecker::propagateFilterFromPre(const CallExpr *CE,
                                                CheckerContext &C) const {

  ProgramStateRef State = C.getState();

  // Getting call name.
  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  StringRef Name = C.getCalleeName(FDecl);

  // Depending on what was untainted at pre-visit, we determined a set of
  // arguments which should be filtered after the function returns. These are
  // stored in the state as TaintArgsOnPostVisit set.
  const TaintInfo *UntaintInfo =
      getTaintInfo(State, Name, TaintInfo::Operation::UNTAINT);
  if (!UntaintInfo)
    return false;

  const ArgVector Arguments = UntaintInfo->getArguments();
  for (ArgVector::const_iterator I = Arguments.begin(), E = Arguments.end();
       I != E; ++I) {
    unsigned ArgNum = *I;

    // Special handling for the tainted return value.
    if (ArgNum == ReturnValueIndex) {
      State = State->removeTaint(CE, C.getLocationContext());
      continue;
    }

    // The arguments are pointer arguments. The data they are pointing at is
    // tainted after the call.
    if (CE->getNumArgs() < (ArgNum + 1))
      continue;

    const Expr *Arg = CE->getArg(ArgNum);
    State = State->removeTaint(Arg, C.getLocationContext());
    SymbolRef Sym = getPointedToSymbol(C, Arg);
    if (Sym)
      State = State->removeTaint(Sym);
  }

  // Clear up the taint info from the state.
  State = State->remove<TaintArgsOnPostVisit>(*UntaintInfo);
  delete UntaintInfo;
  if (State != C.getState()) {
    // Also clear the call info from the state.
    State = removeCallInfo(State, Name);
    C.addTransition(State);
    return true;
  }
  return false;
}

bool CustomTaintChecker::addSourcesPost(const CallExpr *CE,
                                        CheckerContext &C) const {
  // Define the attack surface.
  // Set the evaluation function by switching on the callee name.
  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  if (!isFDApplicable(FDecl))
    return false;

  StringRef Name = C.getCalleeName(FDecl);
  if (Name.empty())
    return false;
  FnCheck evalFunction =
      llvm::StringSwitch<FnCheck>(Name)
          .Case("scanf", &CustomTaintChecker::postScanf)
          // TODO: Add support for vfscanf & family.
          .Case("getchar", &CustomTaintChecker::postRetTaint)
          .Case("getchar_unlocked", &CustomTaintChecker::postRetTaint)
          .Case("getenv", &CustomTaintChecker::postRetTaint)
          .Case("fopen", &CustomTaintChecker::postRetTaint)
          .Case("fdopen", &CustomTaintChecker::postRetTaint)
          .Case("freopen", &CustomTaintChecker::postRetTaint)
          .Case("getch", &CustomTaintChecker::postRetTaint)
          .Case("wgetch", &CustomTaintChecker::postRetTaint)
          .Case("socket", &CustomTaintChecker::postSocket)
          .Default(nullptr);

  // If the callee isn't defined, it is not of security concern.
  // Check and evaluate the call.
  ProgramStateRef State = nullptr;
  if (evalFunction)
    State = (this->*evalFunction)(CE, C);
  if (!State)
    return false;

  // Also clear the call info from the state.
  State = removeCallInfo(State, Name);
  C.addTransition(State);
  return true;
}

ProgramStateRef
CustomTaintChecker::taintMemberAndGlobalVars(SVal Val, const Stmt *S,
                                             ProgramStateRef State) const {

  // It just cares about binary operations(particulary assignments).
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return State;

  Expr *Lhs = BO->getLHS();
  if (isMemberExpr(Lhs) || hasGlobalStorage(Lhs)) {
    SymbolRef Symbol = Val.getAsSymbol();
    if (Symbol) {
      return State->addTaint(Symbol);
    }
  }
  return State;
}

bool CustomTaintChecker::isStdin(const Expr *E, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  SVal Val = State->getSVal(E, C.getLocationContext());

  // stdin is a pointer, so it would be a region.
  const MemRegion *MemReg = Val.getAsRegion();

  // The region should be symbolic, we do not know it's value.
  const SymbolicRegion *SymReg = dyn_cast_or_null<SymbolicRegion>(MemReg);
  if (!SymReg)
    return false;

  // Get it's symbol and find the declaration region it's pointing to.
  const SymbolRegionValue *Sm =
      dyn_cast<SymbolRegionValue>(SymReg->getSymbol());
  if (!Sm)
    return false;
  const DeclRegion *DeclReg = dyn_cast_or_null<DeclRegion>(Sm->getRegion());
  if (!DeclReg)
    return false;

  // This region corresponds to a declaration, find out if it's a global/extern
  // variable named stdin with the proper type.
  if (const VarDecl *D = dyn_cast_or_null<VarDecl>(DeclReg->getDecl())) {
    D = D->getCanonicalDecl();
    if ((D->getName().find("stdin") != StringRef::npos) && D->isExternC())
      if (const PointerType *PtrTy =
              dyn_cast<PointerType>(D->getType().getTypePtr()))
        if (PtrTy->getPointeeType() == C.getASTContext().getFILEType())
          return true;
  }
  return false;
}

// ------------------------------------------ //
//     TaintPropagationRule implementation    //
// ------------------------------------------ //

inline bool
CustomTaintChecker::TaintPropagationRule::isTaintedOrPointsToTainted(
    const Expr *E, ProgramStateRef State, CheckerContext &C) {

  return (State->isTainted(E, C.getLocationContext()) || isStdin(E, C) ||
          (E->getType().getTypePtr()->isPointerType() &&
           State->isTainted(getPointedToSymbol(C, E))));
}

ProgramStateRef
CustomTaintChecker::TaintPropagationRule::process(const CallExpr *CE,
                                                  CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Check for taint in arguments.
  bool IsTainted = false;
  for (ArgVector::const_iterator I = SrcArgs.begin(), E = SrcArgs.end(); I != E;
       ++I) {
    unsigned ArgNum = *I;

    if (ArgNum == InvalidArgIndex) {
      // Check if any of the arguments is tainted, but skip the
      // destination arguments.
      for (unsigned int i = 0; i < CE->getNumArgs(); ++i) {
        if (isDestinationArgument(i))
          continue;
        if ((IsTainted = isTaintedOrPointsToTainted(CE->getArg(i), State, C)))
          break;
      }
      break;
    }

    if (CE->getNumArgs() < (ArgNum + 1))
      return State;
    if ((IsTainted = isTaintedOrPointsToTainted(CE->getArg(ArgNum), State, C)))
      break;
  }
  if (!IsTainted)
    return State;

  // Getting call name.
  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  StringRef Name = C.getCalleeName(FDecl);
  
  TaintInfo TI = TaintInfo(Name, TaintInfo::Operation::TAINT);
  // Mark the arguments which should be tainted after the function returns.
  for (ArgVector::const_iterator I = DstArgs.begin(), E = DstArgs.end(); I != E;
       ++I) {
    unsigned ArgNum = *I;

    // Should we mark all arguments as tainted?
    if (ArgNum == InvalidArgIndex) {
      // For all pointer and references that were passed in:
      // If they are not pointing to const data, mark data as tainted.
      // TODO: So far we are just going one level down; ideally we'd need to
      // recurse here.
      for (unsigned int i = 0; i < CE->getNumArgs(); ++i) {
        const Expr *Arg = CE->getArg(i);
        // Process pointer argument.
        const Type *ArgTy = Arg->getType().getTypePtr();
        QualType PType = ArgTy->getPointeeType();
        if ((!PType.isNull() && !PType.isConstQualified()) ||
            (ArgTy->isReferenceType() && !Arg->getType().isConstQualified()))
          TI.addArgument(i);
      }
      continue;
    }

    // Should mark the return value?
    if (ArgNum == ReturnValueIndex) {
      TI.addArgument(ReturnValueIndex);
      continue;
    }

    // assert(ArgNum < CE->getNumArgs());
    if (ArgNum >= CE->getNumArgs())
      break;
    // Mark the given argument.
    TI.addArgument(ArgNum);
  }
  if (!TI.empty())
    State = State->add<TaintArgsOnPostVisit>(TI);
  return State;
}

// If argument 0 (file descriptor) is tainted, all arguments except for arg 0
// and arg 1 should get taint.
ProgramStateRef CustomTaintChecker::preFscanf(const CallExpr *CE,
                                              CheckerContext &C) const {
  assert(CE->getNumArgs() >= 2);
  ProgramStateRef State = C.getState();
  
  // Check is the file descriptor is tainted.
  if (State->isTainted(CE->getArg(0), C.getLocationContext()) ||
      isStdin(CE->getArg(0), C)) {
    // Getting invocation name.
    const FunctionDecl *FDecl = C.getCalleeDecl(CE);
    StringRef Name = C.getCalleeName(FDecl);
    // All arguments except for the first two should get taint.
    TaintInfo TI = TaintInfo(Name, TaintInfo::Operation::TAINT);
    for (unsigned int i = 2; i < CE->getNumArgs(); ++i){
      TI.addArgument(i);
    }
    return State->add<TaintArgsOnPostVisit>(TI);
  }
  return nullptr;
}

// If argument 0(protocol domain) is network, the return value should get taint.
ProgramStateRef CustomTaintChecker::postSocket(const CallExpr *CE,
                                               CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (CE->getNumArgs() < 3)
    return State;

  SourceLocation DomLoc = CE->getArg(0)->getExprLoc();
  StringRef DomName = C.getMacroNameOrSpelling(DomLoc);
  // White list the internal communication protocols.
  if (DomName.equals("AF_SYSTEM") || DomName.equals("AF_LOCAL") ||
      DomName.equals("AF_UNIX") || DomName.equals("AF_RESERVED_36"))
    return State;
  State = State->addTaint(CE, C.getLocationContext());
  return State;
}

ProgramStateRef CustomTaintChecker::postScanf(const CallExpr *CE,
                                              CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (CE->getNumArgs() < 2)
    return State;

  // All arguments except for the very first one should get taint.
  for (unsigned int i = 1; i < CE->getNumArgs(); ++i) {
    // The arguments are pointer arguments. The data they are pointing at is
    // tainted after the call.
    const Expr *Arg = CE->getArg(i);
    SymbolRef Sym = getPointedToSymbol(C, Arg);
    if (Sym)
      State = State->addTaint(Sym);
  }
  return State;
}

ProgramStateRef CustomTaintChecker::postRetTaint(const CallExpr *CE,
                                                 CheckerContext &C) const {
  return C.getState()->addTaint(CE, C.getLocationContext());
}

static bool getPrintfFormatArgumentNum(const CallExpr *CE,
                                       const CheckerContext &C,
                                       unsigned int &ArgNum) {
  // Find if the function contains a format string argument.
  // Handles: fprintf, printf, sprintf, snprintf, vfprintf, vprintf, vsprintf,
  // vsnprintf, syslog, custom annotated functions.
  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  if (!FDecl)
    return false;
  for (const auto *Format : FDecl->specific_attrs<FormatAttr>()) {
    ArgNum = Format->getFormatIdx() - 1;
    if ((Format->getType()->getName() == "printf") && CE->getNumArgs() > ArgNum)
      return true;
  }

  // Or if a function is named setproctitle (this is a heuristic).
  if (C.getCalleeName(CE).find("setproctitle") != StringRef::npos) {
    ArgNum = 0;
    return true;
  }

  return false;
}

bool CustomTaintChecker::checkUncontrolledFormatString(
    const CallExpr *CE, CheckerContext &C) const {
  // Check if the function contains a format string argument.
  unsigned int ArgNum = 0;
  if (!getPrintfFormatArgumentNum(CE, C, ArgNum))
    return false;

  // If either the format string content or the pointer itself are tainted,warn.
  if (generateReportIfTainted(CE->getArg(ArgNum), MsgUncontrolledFormatString,
                              C))
    return true;
  return false;
}

bool CustomTaintChecker::checkSystemCall(const CallExpr *CE, StringRef Name,
                                         CheckerContext &C) const {
  // TODO: It might make sense to run this check on demand. In some cases,
  // we should check if the environment has been cleansed here. We also might
  // need to know if the user was reset before these calls(seteuid).
  unsigned ArgNum = llvm::StringSwitch<unsigned>(Name)
                        .Case("system", 0)
                        .Case("popen", 0)
                        .Case("execl", 0)
                        .Case("execle", 0)
                        .Case("execlp", 0)
                        .Case("execv", 0)
                        .Case("execvp", 0)
                        .Case("execvP", 0)
                        .Case("execve", 0)
                        .Case("dlopen", 0)
                        .Default(UINT_MAX);

  if (ArgNum == UINT_MAX || CE->getNumArgs() < (ArgNum + 1))
    return false;

  if (generateReportIfTainted(CE->getArg(ArgNum), MsgSanitizeSystemArgs, C))
    return true;

  return false;
}

// TODO: Should this check be a part of the CString checker?
// If yes, should taint be a global setting?
bool CustomTaintChecker::checkTaintedBufferSize(const CallExpr *CE,
                                                const FunctionDecl *FDecl,
                                                CheckerContext &C) const {
  // If the function has a buffer size argument, set ArgNum.
  unsigned ArgNum = InvalidArgIndex;
  unsigned BId = 0;
  if ((BId = FDecl->getMemoryFunctionKind()))
    switch (BId) {
    case Builtin::BImemcpy:
    case Builtin::BImemmove:
    case Builtin::BIstrncpy:
      ArgNum = 2;
      break;
    case Builtin::BIstrndup:
      ArgNum = 1;
      break;
    default:
      break;
    };

  if (ArgNum == InvalidArgIndex) {
    if (C.isCLibraryFunction(FDecl, "malloc") ||
        C.isCLibraryFunction(FDecl, "calloc") ||
        C.isCLibraryFunction(FDecl, "alloca"))
      ArgNum = 0;
    else if (C.isCLibraryFunction(FDecl, "memccpy"))
      ArgNum = 3;
    else if (C.isCLibraryFunction(FDecl, "realloc"))
      ArgNum = 1;
    else if (C.isCLibraryFunction(FDecl, "bcopy"))
      ArgNum = 2;
  }

  if (ArgNum != InvalidArgIndex && CE->getNumArgs() > ArgNum &&
      generateReportIfTainted(CE->getArg(ArgNum), MsgTaintedBufferSize, C))
    return true;

  return false;
}

bool CustomTaintChecker::generateReportIfTainted(const Expr *E,
                                                 const char Msg[],
                                                 CheckerContext &C) const {
  assert(E);

  // Check for taint.
  ProgramStateRef State = C.getState();
  SymbolRef Sym = getPointedToSymbol(C, E);
  if (!State->isTainted(Sym) && !State->isTainted(E, C.getLocationContext()))
    return false;

  // Building message.
  std::string WarningMsg = replaceMessage(Msg, exprToString(E).data());

  return EmitReportTaintedOnDestination(E, WarningMsg.data(), C, Sym);
}

void CustomTaintChecker::setConfiguration(TaintParser TP) const {
  SourceList = TP.getSourceList();
  PropagationRuleList = TP.getPropagationRuleList();
  DestinationList = TP.getDestinationList();
  FilterList = TP.getFilterList();
}

bool CustomTaintChecker::isSourceExpression(StringRef Name,
                                            StringRef CalleeType) const {
  if (Source *Source = getSourceExpression(Name, CalleeType)) {
    delete Source;
    return true;
  }
  return false;
}

Source *CustomTaintChecker::getSourceExpression(StringRef Name,
                                                StringRef CalleeType) const {
  for (SourceList::const_iterator I = SourceList.begin(), E = SourceList.end();
       I != E; ++I) {
    Source Source = *I;
    if (Name.equals_lower(Source.getName()) &&
        (CalleeType.equals_lower(Source.getCalleeType()) ||
         StringRef(Source.getCalleeType()).equals_lower(CALLEETYPEALL))) {
      return new class Source(Source.getName(), Source.getCalleeType(),
                              Source.getArgs());
    }
  }
  return nullptr;
}

CustomTaintChecker::TaintPropagationRule
CustomTaintChecker::getPropagatorExpression(StringRef Name,
                                            StringRef CalleeType) const {
  TaintPropagationRule taintPropagationRule = TaintPropagationRule();
  for (PropagationList::const_iterator I = PropagationRuleList.begin(),
                                       E = PropagationRuleList.end();
       I != E; ++I) {
    Propagator Propagator = *I;
    if (Name.equals_lower(Propagator.getName()) &&
        (CalleeType.equals_lower(Propagator.getCalleeType()) ||
         StringRef(Propagator.getCalleeType()).equals_lower(CALLEETYPEALL))) {
      taintPropagationRule.setSrcArg(Propagator.getSourceArgs());
      taintPropagationRule.setDstArg(Propagator.getDestArgs());
      return taintPropagationRule;
    }
  }
  return taintPropagationRule;
}

Sink *CustomTaintChecker::getDestinationExpression(StringRef Name,
                                                   StringRef CalleeType) const {
  for (DestinationList::const_iterator I = DestinationList.begin(),
                                       E = DestinationList.end();
       I != E; ++I) {
    Sink Sink = *I;
    if (Name.equals_lower(Sink.getName()) &&
        (CalleeType.equals_lower(Sink.getCalleeType()) ||
         StringRef(Sink.getCalleeType()).equals_lower(CALLEETYPEALL))) {
      return new class Sink(Sink.getName(), Sink.getCalleeType(),
                            Sink.getArgs());
    }
  }
  return nullptr;
}

Filter *CustomTaintChecker::getFilterExpression(StringRef Name,
                                                StringRef CalleeType) const {
  for (FilterList::const_iterator I = FilterList.begin(), E = FilterList.end();
       I != E; ++I) {
    Filter Filter = *I;
    if (Name.equals_lower(Filter.getName()) &&
        (CalleeType.equals_lower(Filter.getCalleeType()) ||
         StringRef(Filter.getCalleeType()).equals_lower(CALLEETYPEALL))) {
      return new class Filter(Filter.getName(), Filter.getCalleeType(),
                              Filter.getArgs());
    }
  }
  return nullptr;
}

TaintInfo *CustomTaintChecker::getTaintInfo(ProgramStateRef State,
                                           std::string Name,
                                           enum TaintInfo::Operation Op) const {
  TaintArgsOnPostVisitTy TaintInfoSet = State->get<TaintArgsOnPostVisit>();
  for (llvm::ImmutableSet<TaintInfo>::iterator I = TaintInfoSet.begin(),
                                               E = TaintInfoSet.end();
       I != E; ++I) {
    TaintInfo TI = *I;
    if (TI.getName() == Name && TI.getOperation() == Op)
      return new TaintInfo(TI.getName(), TI.getOperation(), TI.getArguments());
  }
  return nullptr;
}

CallInfo *CustomTaintChecker::getCallInfo(ProgramStateRef State,
                                          std::string Name) const {
  UpperCallInfoTy CallInfoSet = State->get<UpperCallInfo>();
  for (llvm::ImmutableSet<CallInfo>::iterator I = CallInfoSet.begin(),
                                              E = CallInfoSet.end();
       I != E; ++I) {
    CallInfo CI = *I;
    if (CI.Name == Name)
      return new CallInfo(CallInfo(CI.Name, CI.CalleeType));
  }
  return nullptr;
}

bool CustomTaintChecker::EmitReportTaintedOnDestination(
    const Expr *Expr, const char Msg[], CheckerContext &C,
    SymbolRef Symbol) const {
  if (ExplodedNode *N = C.addTransition()) {

    // Should the visitor do a symbol lookup for tainting?
    bool SymbolLookup = false;
    if (C.getState()->isTainted(Symbol))
      SymbolLookup = true;

    initBugType();
    auto report = llvm::make_unique<BugReport>(*UseTaintedBugType, Msg, N);
    report->addRange(Expr->getSourceRange());
    report->markInteresting(Symbol);
    report->addVisitor(
        llvm::make_unique<TaintBugVisitor>(Symbol, Expr, SymbolLookup));
    C.emitReport(std::move(report));
    return true;
  }
  return false;
}

void ento::registerCustomTaintChecker(CheckerManager &mgr) {
  CustomTaintChecker *checker = mgr.registerChecker<CustomTaintChecker>();
  std::string ConfigurationFilePath =
      mgr.getAnalyzerOptions().getOptionAsString("ConfigurationFile", "",
                                                 checker);
  std::string DebugFilePath =
      mgr.getAnalyzerOptions().getOptionAsString("DebugFile", "", checker);
  checker->initialization(ConfigurationFilePath, DebugFilePath);
}
