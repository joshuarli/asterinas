// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <grp.h>
#include <linux/fib_rules.h>
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../common/test.h"
#include "rtnl_common.h"

static int rule_request(int fd,int operation,uint32_t seq)
{
 struct {struct fib_rule_hdr body;uint8_t attributes[64];} rule={.body={.family=AF_INET,.action=FR_ACT_PROHIBIT}};
 uint32_t priority=100,mark=0,mask=255;size_t len=sizeof(rule.body);
 len=rtnl_put(&rule,len,FRA_PRIORITY,&priority,4);len=rtnl_put(&rule,len,FRA_FWMARK,&mark,4);len=rtnl_put(&rule,len,FRA_FWMASK,&mask,4);
 uint16_t flags=NLM_F_REQUEST|NLM_F_ACK;if(operation==RTM_NEWRULE)flags|=NLM_F_CREATE|NLM_F_EXCL;
 struct rtnl_reply reply;if(rtnl_send(fd,operation,flags,seq,&rule,len)||rtnl_receive(fd,&reply,seq)||!reply.saw_error)return -999;
 return reply.error;
}
static int route_error(void)
{
 int fd=socket(AF_INET,SOCK_DGRAM,0);if(fd<0)return -1;
 struct sockaddr_in peer={.sin_family=AF_INET,.sin_port=htons(42568)};inet_pton(AF_INET,"198.51.100.9",&peer.sin_addr);
 int result=connect(fd,(struct sockaddr *)&peer,sizeof(peer));int error=errno;close(fd);errno=0;return result==0?0:error;
}
static int contains_rule(int fd,uint32_t seq)
{
 struct fib_rule_hdr req={.family=AF_INET};struct rtnl_reply reply;
 if(rtnl_send(fd,RTM_GETRULE,NLM_F_REQUEST|NLM_F_DUMP,seq,&req,sizeof(req))||rtnl_receive(fd,&reply,seq)||!reply.saw_done)return -1;
 for(struct nlmsghdr *h=rtnl_first(&reply);h;h=rtnl_next(&reply,h)){
  if(h->nlmsg_type!=RTM_NEWRULE)continue;
  struct fib_rule_hdr *r=NLMSG_DATA(h);
  struct rtattr *first=(struct rtattr *)((char *)r+NLMSG_ALIGN(sizeof(*r)));size_t n=h->nlmsg_len-NLMSG_LENGTH(sizeof(*r));
  struct rtattr *p=rtnl_find(first,n,FRA_PRIORITY),*mask=rtnl_find(first,n,FRA_FWMASK);
  if(r->family==AF_INET&&r->action==FR_ACT_PROHIBIT&&p&&*(uint32_t *)RTA_DATA(p)==100&&mask&&*(uint32_t *)RTA_DATA(mask)==255)return 1;
 }
 return 0;
}
FN_TEST(masked_policy_rule_lifecycle)
{
 int fd=TEST_SUCC(rtnl_open(0));if(fd<0){__TEST_SUMMARY();return;}
 TEST_RES(route_error(),_ret==ENETUNREACH);
 TEST_RES(rule_request(fd,RTM_NEWRULE,121),_ret==0);
 TEST_RES(rule_request(fd,RTM_NEWRULE,125),_ret==-EEXIST);
 pid_t child=TEST_SUCC(fork());if(child==0){
  if(setgroups(0,NULL)||setresgid(65534,65534,65534)||setresuid(65534,65534,65534))_exit(2);
  int nl=rtnl_open(0);if(nl<0)_exit(3);int result=rule_request(nl,RTM_NEWRULE,126);close(nl);_exit(result==-EPERM?0:4);
 }
 if(child>0){int status=0;TEST_RES(waitpid(child,&status,0),_ret==child);TEST_RES(WIFEXITED(status)&&WEXITSTATUS(status)==0,_ret==1);}
 TEST_RES(contains_rule(fd,122),_ret==1);
 TEST_RES(route_error(),_ret==EACCES);
 TEST_RES(rule_request(fd,RTM_DELRULE,123),_ret==0);
 TEST_RES(contains_rule(fd,124),_ret==0);
 TEST_RES(route_error(),_ret==ENETUNREACH);
 TEST_SUCC(close(fd));
}
END_TEST()

static int source_rule_request(int fd,int operation,uint32_t seq)
{
 struct {struct fib_rule_hdr body;uint8_t attributes[64];} rule={.body={.family=AF_INET,.src_len=32,.action=FR_ACT_PROHIBIT}};
 struct in_addr source;inet_pton(AF_INET,"203.0.113.17",&source);uint32_t priority=99;size_t len=sizeof(rule.body);
 len=rtnl_put(&rule,len,FRA_PRIORITY,&priority,4);len=rtnl_put(&rule,len,FRA_SRC,&source,4);
 uint16_t flags=NLM_F_REQUEST|NLM_F_ACK;if(operation==RTM_NEWRULE)flags|=NLM_F_CREATE|NLM_F_EXCL;
 struct rtnl_reply reply;if(rtnl_send(fd,operation,flags,seq,&rule,len)||rtnl_receive(fd,&reply,seq)||!reply.saw_error)return -999;
 return reply.error;
}
FN_TEST(source_selector_is_not_silently_discarded)
{
 int fd=TEST_SUCC(rtnl_open(0));if(fd<0){__TEST_SUMMARY();return;}
 int result=source_rule_request(fd,RTM_NEWRULE,130);
 TEST_RES(result,_ret==0||_ret==-EOPNOTSUPP);
 TEST_RES(route_error(),_ret==ENETUNREACH);
 if(result==0){
  struct fib_rule_hdr req={.family=AF_INET};struct rtnl_reply reply;
  TEST_SUCC(rtnl_send(fd,RTM_GETRULE,NLM_F_REQUEST|NLM_F_DUMP,131,&req,sizeof(req)));
  TEST_SUCC(rtnl_receive(fd,&reply,131));int found=0;struct in_addr expected;inet_pton(AF_INET,"203.0.113.17",&expected);
  for(struct nlmsghdr *h=rtnl_first(&reply);h;h=rtnl_next(&reply,h)){
   if(h->nlmsg_type!=RTM_NEWRULE)continue;
   struct fib_rule_hdr *r=NLMSG_DATA(h);size_t n=h->nlmsg_len-NLMSG_LENGTH(sizeof(*r));
   struct rtattr *a=(struct rtattr *)((char *)r+NLMSG_ALIGN(sizeof(*r)));struct rtattr *src=rtnl_find(a,n,FRA_SRC);
   if(r->src_len==32&&src&&RTA_PAYLOAD(src)==4&&!memcmp(RTA_DATA(src),&expected,4))found=1;
  }
  TEST_RES(found,_ret==1);TEST_RES(source_rule_request(fd,RTM_DELRULE,132),_ret==0);
 }
 TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(rule_changes_notify_ipv4_rule_subscribers)
{
 int listener=TEST_SUCC(rtnl_open(RTMGRP_IPV4_RULE));int fd=TEST_SUCC(rtnl_open(0));
 if(listener<0||fd<0){if(listener>=0)close(listener);if(fd>=0)close(fd);__TEST_SUMMARY();return;}
 TEST_RES(rule_request(fd,RTM_NEWRULE,141),_ret==0);
 struct pollfd event={.fd=listener,.events=POLLIN};int ready=TEST_RES(poll(&event,1,2000),_ret==1);
 if(ready==1){unsigned char buffer[2048];ssize_t n=recv(listener,buffer,sizeof(buffer),0);struct nlmsghdr *h=(void *)buffer;
  TEST_RES(n,_ret>=(ssize_t)NLMSG_LENGTH(sizeof(struct fib_rule_hdr))&&h->nlmsg_type==RTM_NEWRULE);
  if(n>=(ssize_t)NLMSG_LENGTH(sizeof(struct fib_rule_hdr))){struct fib_rule_hdr *rule=NLMSG_DATA(h);TEST_RES(rule->action,_ret==FR_ACT_PROHIBIT);}
 }
 TEST_RES(rule_request(fd,RTM_DELRULE,142),_ret==0);ready=TEST_RES(poll(&event,1,2000),_ret==1);
 if(ready==1){unsigned char buffer[2048];ssize_t n=recv(listener,buffer,sizeof(buffer),0);struct nlmsghdr *h=(void *)buffer;
  TEST_RES(n,_ret>=(ssize_t)NLMSG_LENGTH(sizeof(struct fib_rule_hdr))&&h->nlmsg_type==RTM_DELRULE);
 }
 TEST_SUCC(close(fd));TEST_SUCC(close(listener));
}
END_TEST()

static int zero_mark_rule_request(int fd,int operation,uint32_t seq)
{
 struct {struct fib_rule_hdr body;uint8_t attributes[32];} rule={.body={.family=AF_INET,.action=FR_ACT_PROHIBIT}};
 uint32_t priority=101,mark=0;size_t len=sizeof(rule.body);
 len=rtnl_put(&rule,len,FRA_PRIORITY,&priority,4);len=rtnl_put(&rule,len,FRA_FWMARK,&mark,4);
 uint16_t flags=NLM_F_REQUEST|NLM_F_ACK;if(operation==RTM_NEWRULE)flags|=NLM_F_CREATE|NLM_F_EXCL;
 struct rtnl_reply reply;if(rtnl_send(fd,operation,flags,seq,&rule,len)||rtnl_receive(fd,&reply,seq)||!reply.saw_error)return -999;
 return reply.error;
}
FN_TEST(zero_mark_without_mask_is_an_unrestricted_rule)
{
 int fd=TEST_SUCC(rtnl_open(0));if(fd<0){__TEST_SUMMARY();return;}
 TEST_RES(zero_mark_rule_request(fd,RTM_NEWRULE,151),_ret==0);
 struct fib_rule_hdr req={.family=AF_INET};struct rtnl_reply reply;
 TEST_SUCC(rtnl_send(fd,RTM_GETRULE,NLM_F_REQUEST|NLM_F_DUMP,152,&req,sizeof(req)));TEST_SUCC(rtnl_receive(fd,&reply,152));
 int found=0;for(struct nlmsghdr *h=rtnl_first(&reply);h;h=rtnl_next(&reply,h)){
  if(h->nlmsg_type!=RTM_NEWRULE)continue;
  struct fib_rule_hdr *r=NLMSG_DATA(h);size_t n=h->nlmsg_len-NLMSG_LENGTH(sizeof(*r));
  struct rtattr *a=(struct rtattr *)((char *)r+NLMSG_ALIGN(sizeof(*r)));struct rtattr *p=rtnl_find(a,n,FRA_PRIORITY);
  if(!p||*(uint32_t *)RTA_DATA(p)!=101)continue;
  struct rtattr *mark=rtnl_find(a,n,FRA_FWMARK),*mask=rtnl_find(a,n,FRA_FWMASK),*proto=rtnl_find(a,n,FRA_PROTOCOL);
  found=mark==NULL&&mask==NULL&&proto&&*(uint8_t *)RTA_DATA(proto)==0;
 }
 TEST_RES(found,_ret==1);TEST_RES(route_error(),_ret==EACCES);
 TEST_RES(zero_mark_rule_request(fd,RTM_DELRULE,153),_ret==0);TEST_SUCC(close(fd));
}
END_TEST()
