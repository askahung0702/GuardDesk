// Exercise the production completion reducer; no ETW session or OS file access.
#include "document_trace.cpp"
#include <cassert>
#include <cstdio>
int main(){
    assert(contentSizeInfo(69,20));
    assert(!contentSizeInfo(69,4));assert(!contentSizeInfo(69,19));assert(!contentSizeInfo(74,20));
    Record r={};r.op=69;r.pid=123;r.bytes=0;
    assert(completeRecord(r,0,123,1)&&r.op==69&&r.bytes==0);
    r={};r.op=69;r.pid=123;r.bytes=42;assert(completeRecord(r,0,0,1)&&r.bytes==42);
    r.pid=4;assert(!completeRecord(r,0,0,1));
    r.pid=0;assert(!completeRecord(r,0,0,1));
    r.pid=123;assert(!completeRecord(r,259,0,1));assert(!completeRecord(r,0xc0000022,0,1));
    assert(!completeRecord(r,0,0,10001));
    r={};r.op=64;r.offset=4ull<<24;assert(completeRecord(r,0,3,1)&&r.op==65537&&r.offset==0);
    r={};r.op=64;r.offset=5ull<<24;assert(completeRecord(r,0,3,1)&&r.op==65537);
    r={};r.op=64;assert(completeRecord(r,0,0,1)&&r.op==65537);
    r={};r.op=64;r.offset=1ull<<24;assert(!completeRecord(r,0,0,1));
    r={};r.op=64;r.offset=1ull<<24;assert(!completeRecord(r,0,3,1));
    r={};r.op=64;r.offset=1ull<<24;assert(completeRecord(r,0,1,1)&&r.op==64&&r.offset==0);
    r={};r.op=64;assert(!completeRecord(r,0,2,1));
    r={};r.op=68;r.bytes=1024;r.pid=4;assert(completeRecord(r,0,512,1)&&r.bytes==512);
    r={};r.op=68;r.bytes=1024;assert(!completeRecord(r,0,2048,1));
    r={};r.op=68;r.bytes=1024;assert(!completeRecord(r,259,512,1));
    r={};r.op=67;assert(completeRecord(r,0,128,1)&&r.bytes==128);
    r={};r.op=68;assert(!completeRecord(r,0,0,1));
    r={};r.op=64;r.offset=4ull<<24;r.bytes=1;
    assert(completeRecord(r,0,3,1)&&r.op==(65537|NonDirectoryFlag)&&r.bytes==0);
    r={};r.op=68|NonDirectoryFlag;r.bytes=1024;
    assert(completeRecord(r,0,512,1)&&r.op==(68|NonDirectoryFlag)&&r.bytes==512);
    assert(gd_trace_write_activity_version()==3);
    std::puts("PASS production EOF/overwrite/write/read completion reducer; trace_started=false");
}
