#pragma once
#include "recovery_policy.hpp"
#include <windows.h>

namespace service_recovery {
// Shared product/probe orchestration. Wait is cancelable by the existing SCM
// stop event; there is no queued SCM action and no extra worker process owner.
template<class State,class Launch,class Wait,class Clock,class Stopping>
DWORD supervise(State& state,Launch launch,Wait wait,Clock clock,Stopping stopping){
    auto finish=[&](DWORD error){
        if(error){state.record.last_error=error;if(!state.record.first_error)state.record.first_error=error;}
        // Stop cancels restart, but must not discard a simultaneous AV refusal.
        if(error==225 || error==226 || error==1260)hold(state.record,security,error,clock());
        stopped(state.record,clock());state.save();return DWORD(0);
    };
    if(stopping())return finish(0);
    if(state.security_marker() || state.record.hold!=none)return ERROR_ACCESS_DISABLED_BY_POLICY;
    if(clock()<state.record.updated){hold(state.record,review,ERROR_TIME_SKEW,state.record.updated);state.save();return ERROR_TIME_SKEW;}
    // A previous host died while active/waiting. Reserve another bounded attempt
    // before launch; a reboot is not permission to forget its retry budget.
    if(state.record.phase==active || state.record.phase==waiting){
        const auto delay=failure(state.record,ERROR_PROCESS_ABORTED,clock());state.save();
        if(!delay)return ERROR_PROCESS_ABORTED;
        if(wait(delay))return finish(0);
    }
    for(;;){
        if(stopping())return finish(0);
        if(state.security_marker() || state.record.hold!=none)return ERROR_ACCESS_DISABLED_BY_POLICY;
        if(clock()<state.record.updated){hold(state.record,review,ERROR_TIME_SKEW,state.record.updated);state.save();return ERROR_TIME_SKEW;}
        state.record.phase=active;state.record.updated=clock();state.save();
        const DWORD error=launch();
        // Explicit SCM stop/update/removal wins even if cleanup returned an error.
        // Keep the exit code locally, but never restart a deliberately stopped job.
        if(stopping())return finish(error);
        if(!error)return finish(0); // Includes the existing successful decommission.
        if(state.security_marker())return error;
        const auto delay=failure(state.record,error,clock());state.save();
        if(!delay)return error;
        if(wait(delay))return finish(0);
    }
}
}
