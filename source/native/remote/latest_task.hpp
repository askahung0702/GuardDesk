#pragma once
#include <windows.h>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <optional>
#include <thread>
#include <exception>
#include <stdexcept>
#include <cstdint>

namespace remote {
// One active job, one latest request, one latest result. The factory, processor,
// and its OS resources all live/die on the worker thread. No authority cache.
template<class Request,class Result> class LatestTask {
    std::mutex mutex_;std::condition_variable wake_;
    std::optional<Request> pending_;std::optional<Result> ready_;
    std::exception_ptr error_;std::uint64_t revision_=0;bool stop_=false;
    HANDLE done_=nullptr,available_=nullptr;std::thread thread_;
public:
    using Processor=std::function<Result(Request)>;
    explicit LatestTask(std::function<Processor()> factory){
        done_=CreateEventW(nullptr,TRUE,FALSE,nullptr);available_=CreateEventW(nullptr,TRUE,FALSE,nullptr);
        if(!done_ || !available_){if(done_)CloseHandle(done_);if(available_)CloseHandle(available_);throw std::runtime_error("latest_task_event");}
        try{thread_=std::thread([this,factory=std::move(factory)]{
            try{auto process=factory();
                for(;;){std::optional<Request> request;std::uint64_t revision=0;
                    {std::unique_lock<std::mutex> lock(mutex_);wake_.wait(lock,[&]{return stop_ || pending_.has_value();});
                        if(stop_)break;request=std::move(pending_);pending_.reset();revision=revision_;}
                    auto result=process(std::move(*request));
                    {std::lock_guard<std::mutex> lock(mutex_);if(!stop_ && revision==revision_){ready_=std::move(result);SetEvent(available_);}}
                }
            }catch(...){std::lock_guard<std::mutex> lock(mutex_);error_=std::current_exception();SetEvent(available_);}
            SetEvent(done_);
        });}catch(...){CloseHandle(done_);CloseHandle(available_);done_=available_=nullptr;throw;}
    }
    LatestTask(const LatestTask&)=delete;LatestTask& operator=(const LatestTask&)=delete;
    ~LatestTask(){
        {std::lock_guard<std::mutex> lock(mutex_);stop_=true;pending_.reset();ready_.reset();}wake_.notify_one();
        // A driver that never returns cannot be detached onto freed memory.
        // Fail this disposable worker; broker job teardown closes the cohort.
        if(WaitForSingleObject(done_,2000)!=WAIT_OBJECT_0){TerminateProcess(GetCurrentProcess(),0xe0000095u);for(;;)Sleep(INFINITE);}
        thread_.join();CloseHandle(done_);CloseHandle(available_);
    }
    void submit(Request value){std::lock_guard<std::mutex> lock(mutex_);if(error_)std::rethrow_exception(error_);if(stop_)return;pending_=std::move(value);wake_.notify_one();}
    HANDLE ready_event()const{return available_;} // borrowed; owner lifetime
    void invalidate(){std::lock_guard<std::mutex> lock(mutex_);++revision_;pending_.reset();ready_.reset();ResetEvent(available_);}
    std::optional<Result> take(){std::lock_guard<std::mutex> lock(mutex_);if(error_)std::rethrow_exception(error_);auto value=std::move(ready_);ready_.reset();ResetEvent(available_);return value;}
};
}
