#!/usr/bin/env python3
"""
Performance and Load Testing Suite for PII Incident Redaction Pipeline
"""

import asyncio
import json
import time
import statistics
from pathlib import Path
import sys
from typing import List, Dict, Any
import random
import string

# Add src to path
sys.path.append(str(Path(__file__).parent.parent / "src"))
sys.path.append(str(Path(__file__).parent.parent))

from src.parallel_processing_pipeline import ParallelPIIProcessingPipeline, ProcessingConfig

class LoadTestSuite:
    """Load testing suite for the PII redaction pipeline"""
    
    def __init__(self):
        self.results = []
    
    def generate_test_incidents(self, count: int) -> List[Dict[str, Any]]:
        """Generate test incidents for load testing"""
        
        incidents = []
        for i in range(count):
            # Generate random PII data
            email = f"user{i}@example.com"
            phone = f"+1-555-{random.randint(100, 999)}-{random.randint(1000, 9999)}"
            name = f"User {i}"
            ssn = f"{random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"
            
            # Create incident with PII
            incident = {
                'id': f'load_test_{i}',
                'title': f'Load Test Incident {i}',
                'description': f'Contact {email} at {phone}. Employee {name} has SSN {ssn}.',
                'summary': f'Incident involving {name} with contact information.',
                'participants': [
                    {'name': name, 'email': email}
                ]
            }
            incidents.append(incident)
        
        return incidents
    
    def generate_large_text(self, size_kb: int) -> str:
        """Generate large text for testing"""
        
        base_text = "Contact john.doe@example.com at +1-555-123-4567. Employee Alice Johnson works in engineering department. "
        target_size = size_kb * 1024  # Convert to bytes
        
        # Repeat base text until we reach target size
        repeated_text = base_text
        while len(repeated_text.encode('utf-8')) < target_size:
            repeated_text += base_text
        
        return repeated_text[:target_size]
    
    async def test_concurrent_load(self, incident_count: int, max_concurrent: int):
        """Test concurrent processing with varying loads"""
        
        print(f"🔄 Testing concurrent load: {incident_count} incidents, max {max_concurrent} concurrent")
        
        # Generate test incidents
        incidents = self.generate_test_incidents(incident_count)
        
        # Configure pipeline
        config = ProcessingConfig(max_concurrent_incidents=max_concurrent)
        pipeline = ParallelPIIProcessingPipeline(use_real_api=False, config=config)
        
        # Measure processing time
        start_time = time.time()
        results = await pipeline.process_multiple_incidents(incidents)
        end_time = time.time()
        
        processing_time = end_time - start_time
        throughput = len(results) / processing_time if processing_time > 0 else 0
        
        result = {
            'test_type': 'concurrent_load',
            'incident_count': incident_count,
            'max_concurrent': max_concurrent,
            'processing_time': processing_time,
            'throughput': throughput,
            'successful_results': len(results),
            'success_rate': len(results) / incident_count if incident_count > 0 else 0
        }
        
        self.results.append(result)
        
        print(f"  ✅ Processed {len(results)}/{incident_count} incidents in {processing_time:.2f}s")
        print(f"  📊 Throughput: {throughput:.2f} incidents/second")
        
        return result
    
    async def test_memory_usage(self, text_size_kb: int):
        """Test memory usage with large documents"""
        
        print(f"🧠 Testing memory usage with {text_size_kb}KB text")
        
        # Generate large text
        large_text = self.generate_large_text(text_size_kb)
        
        # Configure pipeline
        config = ProcessingConfig(chunk_size=1000)  # Small chunks for testing
        pipeline = ParallelPIIProcessingPipeline(use_real_api=False, config=config)
        
        # Measure processing time
        start_time = time.time()
        result = await pipeline.process_text(large_text)
        end_time = time.time()
        
        processing_time = end_time - start_time
        
        result_data = {
            'test_type': 'memory_usage',
            'text_size_kb': text_size_kb,
            'text_length': len(large_text),
            'processing_time': processing_time,
            'chunks_processed': result.parallel_stats.get('chunks_processed', 1),
            'chunk_processing_mode': result.parallel_stats.get('chunk_processing_mode', False)
        }
        
        self.results.append(result_data)
        
        print(f"  ✅ Processed {text_size_kb}KB text in {processing_time:.2f}s")
        print(f"  📊 Chunks processed: {result_data['chunks_processed']}")
        
        return result_data
    
    async def test_scalability(self):
        """Test scalability with increasing loads"""
        
        print("📈 Testing scalability with increasing loads")
        
        test_cases = [
            (10, 2),   # 10 incidents, 2 concurrent
            (20, 4),   # 20 incidents, 4 concurrent
            (50, 8),   # 50 incidents, 8 concurrent
            (100, 10)  # 100 incidents, 10 concurrent
        ]
        
        scalability_results = []
        
        for incident_count, max_concurrent in test_cases:
            result = await self.test_concurrent_load(incident_count, max_concurrent)
            scalability_results.append(result)
        
        # Calculate scalability metrics
        throughputs = [r['throughput'] for r in scalability_results]
        avg_throughput = statistics.mean(throughputs)
        
        print(f"📊 Scalability Summary:")
        print(f"  Average throughput: {avg_throughput:.2f} incidents/second")
        print(f"  Throughput range: {min(throughputs):.2f} - {max(throughputs):.2f}")
        
        return scalability_results
    
    async def test_error_recovery(self):
        """Test error recovery and resilience"""
        
        print("🛡️ Testing error recovery and resilience")
        
        # Create incidents with some that might cause issues
        incidents = []
        
        # Valid incidents
        for i in range(5):
            incidents.append({
                'id': f'valid_{i}',
                'title': f'Valid Incident {i}',
                'description': f'Contact user{i}@example.com'
            })
        
        # Edge case incidents
        incidents.append({
            'id': 'empty_description',
            'title': 'Empty Description',
            'description': ''
        })
        
        incidents.append({
            'id': 'very_long_text',
            'title': 'Very Long Text',
            'description': 'A' * 10000  # Very long text
        })
        
        # Process incidents
        config = ProcessingConfig(max_concurrent_incidents=3)
        pipeline = ParallelPIIProcessingPipeline(use_real_api=False, config=config)
        
        start_time = time.time()
        results = await pipeline.process_multiple_incidents(incidents)
        end_time = time.time()
        
        processing_time = end_time - start_time
        success_rate = len(results) / len(incidents)
        
        result = {
            'test_type': 'error_recovery',
            'total_incidents': len(incidents),
            'successful_results': len(results),
            'success_rate': success_rate,
            'processing_time': processing_time
        }
        
        self.results.append(result)
        
        print(f"  ✅ Processed {len(results)}/{len(incidents)} incidents")
        print(f"  📊 Success rate: {success_rate:.2%}")
        
        return result
    
    async def run_load_tests(self):
        """Run all load tests"""
        
        print("🚀 Running Load Tests")
        print("=" * 40)
        
        # Test concurrent loads
        await self.test_concurrent_load(10, 2)
        await self.test_concurrent_load(25, 5)
        await self.test_concurrent_load(50, 10)
        
        # Test memory usage
        await self.test_memory_usage(10)   # 10KB
        await self.test_memory_usage(50)   # 50KB
        await self.test_memory_usage(100)  # 100KB
        
        # Test scalability
        await self.test_scalability()
        
        # Test error recovery
        await self.test_error_recovery()
        
        return self.results

class PerformanceProfiler:
    """Performance profiling utilities"""
    
    def __init__(self):
        self.profiles = []
    
    async def profile_processing_stages(self, text: str):
        """Profile individual processing stages"""
        
        print("🔍 Profiling individual processing stages")
        
        config = ProcessingConfig()
        pipeline = ParallelPIIProcessingPipeline(use_real_api=False, config=config)
        
        # Profile deterministic extraction
        start_time = time.time()
        deterministic_result = await pipeline._run_deterministic_extraction(text)
        deterministic_time = time.time() - start_time
        
        # Profile LLM detection
        start_time = time.time()
        llm_detection_result = await pipeline._run_llm_detection_with_semaphore(deterministic_result)
        llm_detection_time = time.time() - start_time
        
        # Profile LLM verification
        start_time = time.time()
        llm_verification_result = await pipeline._run_llm_verification_with_semaphore(llm_detection_result)
        llm_verification_time = time.time() - start_time
        
        # Profile arbitration
        start_time = time.time()
        arbitration_result = await pipeline._run_arbitration_parallel(
            deterministic_result, llm_detection_result, llm_verification_result
        )
        arbitration_time = time.time() - start_time
        
        # Profile validation
        start_time = time.time()
        validation_result = await pipeline._run_validation_parallel(arbitration_result)
        validation_time = time.time() - start_time
        
        profile = {
            'deterministic_time': deterministic_time,
            'llm_detection_time': llm_detection_time,
            'llm_verification_time': llm_verification_time,
            'arbitration_time': arbitration_time,
            'validation_time': validation_time,
            'total_time': (deterministic_time + llm_detection_time + 
                          llm_verification_time + arbitration_time + validation_time)
        }
        
        self.profiles.append(profile)
        
        print(f"📊 Stage Performance:")
        print(f"  Deterministic: {deterministic_time:.3f}s")
        print(f"  LLM Detection: {llm_detection_time:.3f}s")
        print(f"  LLM Verification: {llm_verification_time:.3f}s")
        print(f"  Arbitration: {arbitration_time:.3f}s")
        print(f"  Validation: {validation_time:.3f}s")
        print(f"  Total: {profile['total_time']:.3f}s")
        
        return profile
    
    async def profile_memory_usage(self, text: str):
        """Profile memory usage during processing"""
        
        print("🧠 Profiling memory usage")
        
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        
        # Measure memory before processing
        memory_before = process.memory_info().rss / 1024 / 1024  # MB
        
        # Process text
        pipeline = ParallelPIIProcessingPipeline(use_real_api=False)
        result = await pipeline.process_text(text)
        
        # Measure memory after processing
        memory_after = process.memory_info().rss / 1024 / 1024  # MB
        
        memory_usage = memory_after - memory_before
        
        profile = {
            'memory_before_mb': memory_before,
            'memory_after_mb': memory_after,
            'memory_usage_mb': memory_usage,
            'text_length': len(text)
        }
        
        self.profiles.append(profile)
        
        print(f"📊 Memory Usage:")
        print(f"  Before: {memory_before:.2f} MB")
        print(f"  After: {memory_after:.2f} MB")
        print(f"  Usage: {memory_usage:.2f} MB")
        
        return profile
    
    async def run_profiling(self):
        """Run all profiling tests"""
        
        print("🔍 Running Performance Profiling")
        print("=" * 40)
        
        # Test text
        test_text = "Contact john.doe@example.com at +1-555-123-4567. Employee Alice Johnson works in engineering."
        
        # Profile processing stages
        await self.profile_processing_stages(test_text)
        
        # Profile memory usage
        await self.profile_memory_usage(test_text)
        
        return self.profiles

async def main():
    """Main performance testing runner"""
    
    print("🚀 PII Redaction Pipeline Performance Testing")
    print("=" * 60)
    
    # Run load tests
    load_test_suite = LoadTestSuite()
    load_results = await load_test_suite.run_load_tests()
    
    # Run profiling
    profiler = PerformanceProfiler()
    profile_results = await profiler.run_profiling()
    
    # Compile results
    results = {
        'load_test_results': load_results,
        'profile_results': profile_results,
        'timestamp': time.time(),
        'summary': {
            'total_load_tests': len(load_results),
            'total_profiles': len(profile_results)
        }
    }
    
    # Save results
    with open("performance_test_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n📁 Performance test results saved to performance_test_results.json")
    
    # Print summary
    print(f"\n📊 Performance Testing Summary:")
    print(f"  Load tests completed: {len(load_results)}")
    print(f"  Profiles completed: {len(profile_results)}")
    
    # Calculate average throughput
    throughputs = [r.get('throughput', 0) for r in load_results if 'throughput' in r]
    if throughputs:
        avg_throughput = statistics.mean(throughputs)
        print(f"  Average throughput: {avg_throughput:.2f} incidents/second")

if __name__ == "__main__":
    asyncio.run(main())
