//src/core/Reconciler.h
#pragma once
#include "Identity.h"
#include "../persistence/ComplianceStore.h"
#include <unordered_map>
#include <string>

class Reconciler {
public:
    explicit Reconciler(ComplianceStore& store);

    void runReconciliation(
        const std::unordered_map<std::string, Identity>& hrSource,
        const std::unordered_map<std::string, Identity>& targetSystem
    );

private:
    ComplianceStore& db;
    std::unordered_map<std::string, std::string> riskPolicy;

    std::string generateRunID();
};
