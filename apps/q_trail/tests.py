import pandas as pd
from django.test import TestCase
from q_trail.backend.reconciliation import detect_pass_through_patterns

class QTrailPassThroughTests(TestCase):
    def test_detect_pass_through_patterns(self):
        data = [
            {'Date': '2023-10-01', 'Credit': 1000, 'Debit': 0, 'Counterparty_Name': 'John Doe', 'Counterparty_VPA': 'john@upi'},
            {'Date': '2023-10-02', 'Credit': 0, 'Debit': 900, 'Counterparty_Name': 'Jane Smith'},
            
            {'Date': '2023-10-05', 'Credit': 500, 'Debit': 0, 'Counterparty_Name': 'Alice'},
            {'Date': '2023-10-05', 'Credit': 500, 'Debit': 0, 'Counterparty_Name': 'Bob'},
            {'Date': '2023-10-07', 'Credit': 0, 'Debit': 950, 'Counterparty_Name': 'Charlie', 'Counterparty_VPA': 'charlie@okaxis'},
        ]
        df = pd.DataFrame(data)
        
        patterns, suspicious = detect_pass_through_patterns(df, 'Intermediary')
        
        self.assertEqual(len(patterns), 2)
        
        # Check 1-to-1 pattern
        p1 = patterns[0]
        self.assertEqual(p1['Pattern_Type'], '1-to-1 Pass-Through')
        self.assertIn('John Doe', p1['Person_X_Sender'])
        self.assertIn('Jane Smith', p1['Person_BC_Receiver'])
        self.assertEqual(p1['Amount_Leg_1'], 1000)
        self.assertEqual(p1['Amount_Leg_2'], 900)
        
        # Check merged pattern
        p2 = patterns[1]
        self.assertEqual(p2['Pattern_Type'], 'Merged Funds')
        self.assertIn('Alice', p2['Person_X_Sender'])
        self.assertIn('Bob', p2['Person_X_Sender'])
        self.assertIn('Charlie', p2['Person_BC_Receiver'])
        self.assertEqual(p2['Amount_Leg_1'], 1000)
        self.assertEqual(p2['Amount_Leg_2'], 950)
