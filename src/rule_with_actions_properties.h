/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */


#ifndef SRC_RULE_WITH_ACTIONS_PROPERTIES_H_
#define SRC_RULE_WITH_ACTIONS_PROPERTIES_H_


#include "modsecurity/transaction.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/variable_value.h"
#include "modsecurity/rule.h"
#include "modsecurity/actions/action.h"
#include "src/actions/action_type_rule_metadata.h"
#include "src/actions/action_with_execution.h"
#include "src/actions/disruptive/disruptive_action.h"

namespace modsecurity {

namespace actions {
class Action;
class Severity;
class LogData;
class Msg;
class Rev;
class SetVar;
class Tag;
class XmlNS;
namespace transformations {
class Transformation;
}
}

using Transformation = actions::transformations::Transformation;
using Transformations = std::vector<std::shared_ptr<Transformation>>;

using Action = actions::Action;
using Actions = std::vector<std::shared_ptr<Action>>;

using ActionWithExecution = actions::ActionWithExecution;
using ActionTypeRuleMetaData = actions::ActionTypeRuleMetaData;
using ActionDisruptive = actions::disruptive::ActionDisruptive;

using MatchActions = std::vector<std::shared_ptr<ActionWithExecution > >;
using MatchActionsPtr = std::vector<ActionWithExecution *>;

using Tags = std::vector<std::shared_ptr<actions::Tag> >;
using TagsPtr = std::vector<actions::Tag *>;

using SetVars = std::vector<std::shared_ptr<actions::SetVar> >;
using SetVarsPtr = std::vector<actions::SetVar *>;

using XmlNSs = std::vector<std::shared_ptr<actions::XmlNS> >;
using XmlNSsPtr = std::vector<actions::XmlNS *>;

const int SEVERITY_NOT_SET = 9;
const int ACCURACY_NOT_SET = 9;
const int MATURITY_NOT_SET = 9;


class RuleWithActionsProperties {
    /**
     * Properties that can be part of the SecDefaultActions.
     *
     */
 public:

    RuleWithActionsProperties(Transformations *transformations = nullptr);

    RuleWithActionsProperties(const RuleWithActionsProperties &o);
    RuleWithActionsProperties &operator=(const RuleWithActionsProperties &o);

    void clear() {
        m_containsLogAction = false;
        m_containsNoLogAction = false;
        m_containsStaticBlockAction = false;
        m_actionsSetVar.clear();
        m_actionsTag.clear();
        m_actionDisruptiveAction = nullptr;
        m_actionsRuntimePos.clear();
        m_transformations.clear();
    };

    void populate(const RuleWithActions *r);



    /* auditLog */
    bool containsAuditLog() const noexcept {
        return m_containsAuditLogAction;
    }
    void setAuditLog(bool b) {
        m_containsAuditLogAction = b;
    }


    /* log */
    bool containsLog() const noexcept {
        return m_containsLogAction;
    }
    void setLog(bool b) {
        m_containsLogAction = b;
    }


    /* MultiMatch */
    bool containsMultiMatch() const noexcept {
        return m_containsMultiMatchAction;
    }
    void setMultiMatch(bool b) {
        m_containsMultiMatchAction = b;
    }


    /* noAuditLog */
    bool containsNoAuditLog() const noexcept {
        return m_containsNoAuditLogAction;
    }
    void setNoAuditLog(bool b) {
        m_containsNoAuditLogAction = b;
    }


    /* noLog */
    bool containsNoLog() const noexcept {
        return m_containsNoLogAction;
    }
    void setNoLog(bool b) {
        m_containsNoLogAction = b;
    }


    /* block */
    bool containsBlock() const noexcept {
        return m_containsStaticBlockAction;
    }
    void setBlock(bool b) {
        m_containsStaticBlockAction = b;
    }


    /* transformations */
    const Transformations &getTransformations() const noexcept {
        return m_transformations;
    }
    void addTransformation_(std::shared_ptr<Transformation> t) {
        m_transformations.push_back(t);
    }

    /* tags */
    const Tags &getTags() const noexcept {
        return m_actionsTag;
    }
    void setTags(Tags tags) noexcept {
        m_actionsTag.insert(m_actionsTag.end(), tags.begin(), tags.end());
    }
    void addTag(std::shared_ptr<actions::Tag> t) {
        m_actionsTag.push_back(t);
    }
    bool hasTags() const noexcept {
        return !m_actionsTag.empty();
    }
    void clearTags() noexcept {
        m_actionsTag.clear();
    }

    /* vars */
    const SetVars &getSetVars() const noexcept {
        return m_actionsSetVar;
    }
    void addSetVar(std::shared_ptr<actions::SetVar> t) {
        m_actionsSetVar.push_back(t);
    }
    
    /* other match actions */
    const MatchActions &getGenericMatchActions() const noexcept {
        return m_actionsRuntimePos;
    }
    void addGenericMatchAction(std::shared_ptr<actions::ActionWithExecution> a) {
        m_actionsRuntimePos.push_back(a);
    }
    

 public: /* private */
    std::shared_ptr<ActionDisruptive> m_actionDisruptiveAction;

 private:
    void inline copyActionsWithRunTimeStrings(const RuleWithActionsProperties &o);

    bool m_containsAuditLogAction:1;
    bool m_containsLogAction:1;
    bool m_containsMultiMatchAction:1;
    bool m_containsNoAuditLogAction:1;
    bool m_containsNoLogAction:1;
    bool m_containsStaticBlockAction:1;
    Transformations m_transformations;
    Tags m_actionsTag;
    SetVars m_actionsSetVar;
    MatchActions m_actionsRuntimePos;
    
};

}  // namespace modsecurity


#endif  // SRC_RULE_WITH_ACTIONS_PROPERTIES_H_