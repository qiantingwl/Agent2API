"""Privacy-preserving optimization must be equivalent to the previous scrubber."""
import random,re,unittest
from ui_support import public_value,_public_key


def reference(value):
    if isinstance(value,dict):
        private={'secret','credentials','password','token','accesstoken','refreshtoken','apikey','authorization','cookie','setcookie','credentialversion'}
        return {k:reference(v) for k,v in value.items() if re.sub(r'[^a-z]','',k.lower()) not in private}
    if isinstance(value,list):return [reference(v) for v in value]
    if isinstance(value,str):
        value=re.sub(r'(?i)bearer\s+[A-Za-z0-9._~+/=-]+','Bearer [已隐藏]',value)
        value=re.sub(r'(?i)(https?://)[^\s/@]+:[^\s/@]+@',r'\1[已隐藏]@',value)
        value=re.sub(r'(?i)((?:access[_-]?token|refresh[_-]?token|api[_-]?key|password|secret|token|cookie|authorization)[\"\']?\s*[:=]\s*)[^\s&,;]+',r'\1[已隐藏]',value)
        value=re.sub(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+','[已隐藏]',value)
    return value


class PublicValueCPUTests(unittest.TestCase):
    def test_nested_credentials_and_unicode_match_original(self):
        data={'Access_Token':'fixture','nested':[{'set-cookie':'fixture','safe':True,'message':'BEARER\u2003abc.def https://name:pass@host token=fixture eyJabc.def.ghi'}], 'label':'apİkey: hidden; TOKEN : hidden, password="hidden"'}
        self.assertEqual(public_value(data),reference(data))
        self.assertNotIn('Access_Token',public_value(data))
        self.assertNotIn('fixture',str(public_value(data)))

    def test_varied_literal_combinations_preserve_every_rule(self):
        rng=random.Random(4)
        parts=['plain','中文','bearer\tabc','Bearer\nabc','https://u:p@host','HTTP://a:b@host',"password' = abc",'secret:abc','AUTHORIZATION=abc','eyJabc.def.ghi','x:y','api_key=abc','token:Bearer abc',' ' ,':','=','\u2003','ſecret=abc']
        values=[''.join(rng.choices(parts,k=5)) for _ in range(1500)]
        self.assertEqual(public_value(values),reference(values))

    def test_key_cache_is_bounded_and_does_not_cache_values(self):
        _public_key.cache_clear()
        for n in range(1000):public_value({f'field-{n}':'fixture-value'})
        self.assertLessEqual(_public_key.cache_info().currsize,512)
        before=_public_key.cache_info().currsize
        for n in range(100):public_value({'label':f'private-value-{n}'})
        self.assertLessEqual(_public_key.cache_info().currsize,before+1)


if __name__=='__main__':unittest.main()
