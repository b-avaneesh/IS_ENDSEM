from pathlib import Path
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import types
import unittest

ROOT=Path(__file__).resolve().parents[1]

def load(file):
    m=types.ModuleType('test_domain');m.__file__=str(file)
    exec(compile(file.read_text(encoding='utf-8'),str(file),'exec'),m.__dict__)
    return m

class DomainGeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.g=load(ROOT/'generator.py')
        cls.domain={'title':'Hospital Reports','record_name':'report','fields':[
            {'name':'patient','type':'text','search':True},
            {'name':'department','type':'choice','choices':['Cardiology','Dental'],'search':True,'count':True},
            {'name':'bill','type':'decimal','decimals':2,'sum':True,'search':True},
            {'name':'visits','type':'integer','sum':True}],
            'min_records':2,'use_deadline':False,'close_on_aggregate':False}
        cls.entities={'Reception':['submit_record'],'Doctor':['verify_record','view_record'],
                      'Search Desk':['search_records'],'Finance':['aggregate_records','threshold_decrypt']}

    def test_validation_and_no_overwrite(self):
        with self.assertRaises(ValueError):
            self.g.validate_entities({'Invalid':['unknown']}, self.g.DOMAIN_ACTIONS)
        self.assertEqual(self.g.validate_entities({'Owner':['view_record','submit_record']},
                         self.g.DOMAIN_ACTIONS)['Owner'], ['submit_record','view_record'])
        for fields in [[],[{'name':'bad/name','type':'text'}],
                       [{'name':'x','type':'text','sum':True}],
                       [{'name':'x','type':'choice','choices':['a','A']}]]:
            with self.assertRaises(ValueError):
                self.g.validate_domain({**self.domain,'fields':fields})
        with tempfile.TemporaryDirectory() as temp:
            out=Path(temp)/'new'
            file=self.g.create_domain_solution(self.domain,self.entities,out)
            before=file.read_bytes()
            with self.assertRaises(FileExistsError):
                self.g.create_domain_solution(self.domain,self.entities,out)
            self.assertEqual(before,file.read_bytes())
            m=load(file)
            for bill in ['-1','0.001','NaN','1e99999','1e-9999999']:
                with self.assertRaises(ValueError):
                    m.normalize_record({'patient':'A','department':'Dental','bill':bill,'visits':'1'})
            with self.assertRaises(ValueError):
                m.normalize_record({'patient':'A','department':'unknown','bill':'1','visits':'1'})

    def test_complete_hospital_workflow(self):
        with tempfile.TemporaryDirectory() as temp,contextlib.redirect_stdout(io.StringIO()) as output:
            file=self.g.create_domain_solution(self.domain,self.entities,Path(temp)/'hospital')
            m=load(file)
            m.new_password=lambda label:'pass-'+label
            m.setup()
            m.ROLE='Reception'
            m.submit_record('R1',{'patient':'Alice','department':'Dental','bill':'10.10','visits':'2'})
            m.submit_record('R2',{'patient':'Bob','department':'Dental','bill':'20.20','visits':'3'})
            with self.assertRaises(PermissionError):
                m.view_record('R1')
            m.ROLE='Doctor'
            m.verify_record('R1');m.verify_record('R2')
            self.assertEqual(m.view_record('R1')['bill'],'10.10')
            m.ROLE='Search Desk'
            self.assertEqual(m.find_records('department','DENTAL'),['R1','R2'])
            self.assertEqual(m.find_records('bill','10.1'),['R1'])
            self.assertEqual(m.find_records('patient','alice'),['R1'])
            stamp=m.read('metadata','R1.json')['submitted_at']
            self.assertIn('R1',m.find_records(start=stamp,end=stamp))
            with self.assertRaises(PermissionError):
                m.view_record('R1')
            m.ROLE='Finance'
            m.aggregate_records()
            m.getpass=lambda prompt:'pass-authority 1' if '1' in prompt else 'pass-authority 2'
            totals=m.threshold_decrypt()
            self.assertEqual(totals['Record count'],2)
            self.assertEqual(totals['Total bill'],'30.30')
            self.assertEqual(totals['Total visits'],5)
            self.assertEqual(totals['department = Dental'],2)
            self.assertEqual(totals['department = Cardiology'],0)
            # Persistent keys, role accounts and encrypted search survive restart.
            m=load(file);m.setup();m.ROLE='Search Desk'
            self.assertEqual(m.find_records('patient','alice'),['R1'])
            # An open submission policy allows new records, but blocks stale decryption.
            m.ROLE='Reception'
            m.submit_record('R3',{'patient':'Carol','department':'Cardiology','bill':'0.30','visits':'1'})
            m.ROLE='Finance'
            with self.assertRaises(ValueError):
                m.threshold_decrypt()
            m.ROLE='Doctor';m.verify_record('R3')
            m.ROLE='Finance'
            with self.assertRaises(ValueError):
                m.threshold_decrypt()
            m.aggregate_records()
            m.getpass=lambda prompt:'pass-authority 1' if '1' in prompt else 'pass-authority 2'
            self.assertEqual(m.threshold_decrypt()['Total bill'],'30.60')
            # Tampered record rejected before acceptance.
            cipher=file.parent/'record_files'/'encrypted'/'R1.json'
            value=json.loads(cipher.read_text());cipher.write_text(json.dumps('00'+value[2:]))
            m.ROLE='Doctor'
            with self.assertRaises(ValueError):
                m.verify_record('R1')
            self.assertIn('Hash comparison: MATCH',output.getvalue())
            self.assertIn('Signature comparison: MATCH',output.getvalue())

    def test_domains_and_interactive_generator(self):
        examples=[('University','marks','integer'),('Bank','amount','decimal'),('Warehouse','quantity','integer')]
        with tempfile.TemporaryDirectory() as temp:
            for title,name,kind in examples:
                domain={'title':title,'record_name':'record','fields':[{'name':name,'type':kind,'sum':True}]}
                source,config,_=self.g.build_domain_source(domain,{'Owner':list(self.g.DOMAIN_ACTIONS)})
                compile(source,title,'exec')
                self.assertNotIn('CandidateID=',source)
                self.assertNotIn('def cast_vote(',source)
            # Self-contained generator copied outside the project.
            copy=Path(temp)/'generator.py';copy.write_bytes((ROOT/'generator.py').read_bytes())
            out=Path(temp)/'result'
            answers='\n'.join(['Warehouse','item','2','category','choice','Tools,Parts','y','y',
                                'quantity','integer','n','y','n','n','','','','','','','','2','Supplier','1','Manager','2,5,6',str(out),''])
            run=subprocess.run([sys.executable,str(copy)],input=answers,text=True,capture_output=True,timeout=30)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertTrue((out/'solution.py').exists(),run.stdout)
            m=load(out/'solution.py')
            self.assertEqual(m.DOMAIN['title'],'Warehouse')
            self.assertEqual(m.ENTITIES['Manager'],['verify_record','aggregate_records','threshold_decrypt'])
            # A single entity prompt drives every assigned action in dependency order.
            calls=[]
            m.ROLE='Manager'
            m.verify_record=lambda record_id:calls.append(('verify',record_id))
            m.aggregate_records=lambda:calls.append(('aggregate',None))
            m.threshold_decrypt=lambda:calls.append(('threshold',None))
            answers=iter(['1','ITEM1','2']);m.input=lambda prompt:next(answers)
            with contextlib.redirect_stdout(io.StringIO()):m.entity_menu('Manager')
            self.assertEqual(calls,[('verify','ITEM1'),('aggregate',None),('threshold',None)])

if __name__=='__main__':
    unittest.main(verbosity=2)
