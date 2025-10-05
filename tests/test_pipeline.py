#!/usr/bin/env python3
"""
Test suite for PII Incident Redaction Pipeline
Basic tests to verify pipeline functionality
"""

import asyncio
import json
import tempfile
from pathlib import Path
import sys

# Add src to path
sys.path.append(str(Path(__file__).parent.parent / "src"))
sys.path.append(str(Path(__file__).parent.parent))

from main import PIIRedactionPipeline

class TestPIIRedactionPipeline:
    """Test suite for PII redaction pipeline"""
    
    def __init__(self):
        self.pipeline = PIIRedactionPipeline(use_real_api=False)
        self.test_results = []
    
    async def test_basic_redaction(self):
        """Test basic PII redaction functionality"""
        
        test_text = "Contact john.doe@example.com at +1-555-123-4567"
        
        result = await self.pipeline.process_text(test_text)
        
        # Verify redaction occurred
        assert "[REDACTED_EMAIL]" in result['processed_text']
        assert "[REDACTED_PHONE]" in result['processed_text']
        assert "john.doe@example.com" not in result['processed_text']
        assert "+1-555-123-4567" not in result['processed_text']
        
        self.test_results.append({
            'test': 'basic_redaction',
            'status': 'PASS',
            'message': 'Basic PII redaction working correctly'
        })
    
    async def test_pseudonymization(self):
        """Test pseudonymization functionality"""
        
        test_text = "Employee Alice Johnson works in the engineering department"
        
        result = await self.pipeline.process_text(test_text)
        
        # Verify pseudonymization occurred
        assert "Person_" in result['processed_text']
        assert "Alice Johnson" not in result['processed_text']
        
        # Check pseudonym mapping
        assert len(result['pseudonym_map']) > 0
        
        self.test_results.append({
            'test': 'pseudonymization',
            'status': 'PASS',
            'message': 'Pseudonymization working correctly'
        })
    
    async def test_quality_metrics(self):
        """Test quality metrics calculation"""
        
        test_text = "Email: test@example.com, Phone: +1-555-123-4567"
        
        result = await self.pipeline.process_text(test_text)
        
        # Verify quality metrics exist
        assert 'quality_metrics' in result
        assert 'overall_quality_score' in result['quality_metrics']
        assert 'precision' in result['quality_metrics']
        assert 'recall' in result['quality_metrics']
        
        self.test_results.append({
            'test': 'quality_metrics',
            'status': 'PASS',
            'message': 'Quality metrics calculation working'
        })
    
    async def test_validation_issues(self):
        """Test validation issue detection"""
        
        # Text with explicit PII that should be detected as residual
        test_text = "SSN: 123-45-6789, Credit Card: 4532-1234-5678-9012"
        
        result = await self.pipeline.process_text(test_text)
        
        # Should detect validation issues
        assert result['validation_issues'] > 0
        
        self.test_results.append({
            'test': 'validation_issues',
            'status': 'PASS',
            'message': 'Validation issue detection working'
        })
    
    async def test_file_output(self):
        """Test file output functionality"""
        
        test_text = "Test document with email@example.com"
        
        with tempfile.TemporaryDirectory() as temp_dir:
            result = await self.pipeline.process_text(test_text, temp_dir)
            
            # Check that files were created
            output_path = Path(temp_dir)
            assert (output_path / "redaction_results.json").exists()
            assert (output_path / "stage3_deterministic.json").exists()
            assert (output_path / "stage4_finder.json").exists()
            assert (output_path / "stage5_judge.json").exists()
            assert (output_path / "stage6_arbitration.json").exists()
            assert (output_path / "stage7_validation.json").exists()
            
            # Verify JSON files are valid
            with open(output_path / "redaction_results.json") as f:
                json.load(f)  # Should not raise exception
        
        self.test_results.append({
            'test': 'file_output',
            'status': 'PASS',
            'message': 'File output functionality working'
        })
    
    async def run_all_tests(self):
        """Run all tests"""
        
        print("🧪 Running PII Redaction Pipeline Tests")
        print("=" * 40)
        
        tests = [
            self.test_basic_redaction,
            self.test_pseudonymization,
            self.test_quality_metrics,
            self.test_validation_issues,
            self.test_file_output
        ]
        
        for test in tests:
            try:
                await test()
                print(f"✅ {test.__name__}")
            except Exception as e:
                print(f"❌ {test.__name__}: {e}")
                self.test_results.append({
                    'test': test.__name__,
                    'status': 'FAIL',
                    'message': str(e)
                })
        
        # Summary
        passed = len([r for r in self.test_results if r['status'] == 'PASS'])
        total = len(self.test_results)
        
        print(f"\n📊 Test Summary:")
        print(f"  Passed: {passed}/{total}")
        print(f"  Success rate: {(passed/total)*100:.1f}%")
        
        if passed == total:
            print("🎉 All tests passed!")
        else:
            print("⚠️  Some tests failed. Check the results above.")
        
        return self.test_results

async def main():
    """Main test runner"""
    
    test_suite = TestPIIRedactionPipeline()
    results = await test_suite.run_all_tests()
    
    # Save test results
    with open("test_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n📁 Test results saved to test_results.json")

if __name__ == "__main__":
    asyncio.run(main())
