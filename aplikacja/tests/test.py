import unittest
from argon2 import PasswordHasher
from django.test import TestCase
from rest_framework_simplejwt.tokens import RefreshToken

class PasswordHashingTest(TestCase):
    def set_password(self, raw_password):
        ph = PasswordHasher()
        self.password = ph.hash(raw_password)

    def check_password(self, raw_password):
        ph = PasswordHasher()
        return ph.verify(self.password, raw_password)

    def test_password_hashing(self):
        # Dane testowe
        raw_password = 'testpassword'

        # Haszowanie hasła
        hashed_password = self.set_password(raw_password)

        # sprawdzenie czy haslo jest dobrze zahasowane
        self.assertTrue(self.check_password(raw_password))
        
class JWTTokenTest(TestCase):
    def generate_JWT(self, user_id, roles):
        refresh = RefreshToken()
        refresh['user_id'] = user_id
        refresh['roles'] = roles
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)
        return {'access_token': access_token, 'refresh_token': refresh_token}
    
    def decode_JWT(self, token):
        refresh = RefreshToken(token)
        user_id = refresh.get('user_id')
        roles = refresh.get('roles')
        return {'user_id': user_id, 'roles': roles}
    
    def test_JWT(self):
        #dane testowe
        user_id = 5
        roles = ['admin', 'office_employee']
        
        #generowanie
        token = self.generate_JWT(user_id, roles)
        
        self.assertIn('access_token', token)
        self.assertIn('refresh_token', token)
        
        #dekodowany token
        decoded_token = self.decode_JWT(token['refresh_token'])
        
        #sprawdzenie czy dane sa poprawne po dekodowaniu
        self.assertEqual(decoded_token['user_id'], user_id)
        self.assertEqual(decoded_token['roles'], roles)

if __name__ == '__main__':
    unittest.main()