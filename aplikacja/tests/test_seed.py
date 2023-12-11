from django.test import TestCase
from aplikacja.scripts.seed import seed_database
from aplikacja.models import User, Role, UserRoles

class TestSeeder(TestCase):
    def test_seed_database(self):
        # Call the seed function
        seed_database()

        # Check if the roles were created
        roles = Role.objects.all()
        self.assertEqual(roles.count(), 5)

        # Check if there is one user for each role
        for role in roles:
            user = User.objects.get(username=f"{role.role_name}@epicup.pl")
            user_roles = UserRoles.objects.get(user=user, role=role)
            self.assertIsNotNone(user)
            self.assertIsNotNone(user_roles)

if __name__ == '__main__':
    import unittest
    unittest.main()