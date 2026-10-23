import importlib.util
import json
from pathlib import Path
import struct
import unittest

BASE=Path(__file__).resolve().parents[1]/'adapters/landscape'
spec=importlib.util.spec_from_file_location('landscape_router',BASE/'router.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def policy(learn=True):
    return m.policy_load({'schema_version':1,'clients':['10.10.10.69'],'hint_ttl_seconds':30,
       'applications':{'42':{'approved':True,'flow_id':2,'wan_ifname':'wan2','learn_endpoint':learn,'allow_udp_endpoint_hints':True}},
       'static_endpoints':[]})
def event(appid=42,port=50000,t=1000,action='classification'):
    return {'schema_version':1,'event':action,'appid':appid,'rule_id':7,'observed_at':t,
        'flow':{'direction':'lan_to_wan','ip_version':4,'protocol':'tcp','src_ip':'10.10.10.69',
                'src_port':port,'dst_ip':'203.0.113.5','dst_port':80}}
class FakeBackend:
    def __init__(self):self.values={};self.deleted=[];self.configs=[]
    def put(self,name,key,value):self.values[(name,key)]=value
    def delete(self,name,key):self.values.pop((name,key),None);self.deleted.append((name,key))
    def check_wan(self,*args):pass
    def config(self,*args):self.configs.append(args)

class LandscapeRoutingTests(unittest.TestCase):
    def test_explicit_approval_required(self):
        p={'schema_version':1,'clients':['10.10.10.69'],'applications':{'42':{'flow_id':2}}}
        with self.assertRaises(ValueError):m.policy_load(p)
    def test_ipv6_is_disabled(self):
        with self.assertRaises(ValueError):m.policy_load({'schema_version':1,'clients':['2001:db8::1']})
    def test_empty_clients_rejected(self):
        with self.assertRaises(ValueError):m.policy_load({'schema_version':1,'clients':[]})
    def test_endpoint_key_omits_only_source_port(self):
        a=event()['flow'];b=dict(a,src_port=60000)
        self.assertEqual(m.endpoint_key(a),m.endpoint_key(b))
        self.assertNotEqual(m.endpoint_key(a),m.endpoint_key(dict(b,dst_port=443)))
    def test_hint_does_not_write_live_route_map(self):
        backend=FakeBackend();receiver=m.HintReceiver(policy(),backend)
        result=receiver.process(event(),now=1000,now_ns=1_000_000)
        self.assertEqual(result['current_connection_action'],'unchanged')
        self.assertTrue(backend.values)
        self.assertEqual({name for name,key in backend.values},{'dpi_rt_hint_v1'})
    def test_unknown_reclassification_withdraws_existing_real_map_hint(self):
        backend=FakeBackend();receiver=m.HintReceiver(policy(),backend)
        receiver.process(event(),now=1000,now_ns=1_000_000)
        self.assertEqual(len(backend.values),1)
        receiver.process(event(appid=999,t=1001),now=1001,now_ns=2_000_000)
        self.assertEqual(backend.values,{})
        self.assertEqual(len(backend.deleted),1)
        self.assertEqual(receiver.applied,{})
    def test_same_endpoint_conflicting_app_withdraws(self):
        backend=FakeBackend();receiver=m.HintReceiver(policy(),backend)
        receiver.process(event(),now=1000,now_ns=1_000_000)
        receiver.process(event(appid=999,port=50001,t=1001),now=1001,now_ns=2_000_000)
        self.assertEqual(backend.values,{})
    def test_old_retraction_does_not_remove_new_hint(self):
        backend=FakeBackend();receiver=m.HintReceiver(policy(),backend)
        receiver.process(event(t=1001),now=1001,now_ns=1_000_000)
        out=receiver.process(event(t=1000,action='retraction'),now=1001,now_ns=2_000_000)
        self.assertEqual(out['status'],'ignored_out_of_order');self.assertEqual(len(backend.values),1)
    def test_retraction_only_removes_future_hint(self):
        backend=FakeBackend();receiver=m.HintReceiver(policy(),backend)
        receiver.process(event(),now=1000,now_ns=1_000_000)
        result=receiver.process(event(t=1001,action='retraction'),now=1001,now_ns=2_000_000)
        self.assertEqual(result['current_connection_action'],'unchanged')
        self.assertEqual([x[0] for x in backend.deleted],['dpi_rt_hint_v1'])
    def test_expiry_withdraws_without_touching_connections(self):
        backend=FakeBackend();receiver=m.HintReceiver(policy(),backend)
        receiver.process(event(),now=1000,now_ns=1_000_000)
        receiver.refresh(31*m.NS)
        self.assertEqual(backend.values,{})
    def test_learning_disabled_by_explicit_policy(self):
        receiver=m.HintReceiver(policy(False))
        result=receiver.process(event(),now=1000,now_ns=1_000_000)
        self.assertEqual(result['changes'],[])
    def test_unapproved_client_ignored(self):
        receiver=m.HintReceiver(policy());e=event();e['flow']['src_ip']='10.10.10.70'
        self.assertEqual(receiver.process(e,now=1000,now_ns=1_000_000)['status'],'ignored_unapproved_client')
    def test_static_exact_endpoint_uses_explicit_app(self):
        p=policy(False);p['static'][m.endpoint_key(event()['flow'])]=42
        receiver=m.HintReceiver(p);result=receiver.refresh(1_000_000)
        self.assertEqual(len(result),1);self.assertFalse(result[0]['heuristic'])
    def test_many_endpoints_do_not_write_route_or_nat(self):
        backend=FakeBackend();receiver=m.HintReceiver(policy(),backend)
        for i in range(100):
            e=event(port=40000+i,t=1000+i/1000);e['flow']['dst_ip']='203.0.113.%d'%(i+1)
            receiver.process(e,now=1001,now_ns=1_000_000+i)
        self.assertEqual(len(backend.values),100)
        self.assertEqual({x[0] for x in backend.values},{'dpi_rt_hint_v1'})

if __name__=='__main__':unittest.main()
