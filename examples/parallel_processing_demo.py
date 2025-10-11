#!/usr/bin/env python3
"""
Example demonstrating parallel processing capabilities
"""

import asyncio
import time
import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent / "src"))
sys.path.append(str(Path(__file__).parent.parent))

from main import PIIRedactionPipeline
from src.parallel_processing_pipeline import ParallelPIIProcessingPipeline, ProcessingConfig

async def demonstrate_parallel_processing():
    """Demonstrate parallel processing capabilities"""
    
    print("🚀 PII Redaction Pipeline - Parallel Processing Demo")
    print("=" * 60)
    
    # Test data
    test_texts = [
        "Contact john.doe@example.com at +1-555-123-4567",
        "Employee Alice Johnson works in the engineering department",
        "SSN: 123-45-6789, Credit Card: 4532-1234-5678-9012",
        "Email: support@company.com, Phone: +1-800-555-0199",
        "Customer: Bob Smith, Address: 123 Main St, City, State 12345"
    ]
    
    print(f"📝 Processing {len(test_texts)} test documents...")
    
    # Sequential processing
    print("\n🔄 Sequential Processing:")
    sequential_pipeline = PIIRedactionPipeline(use_real_api=False)
    
    start_time = time.time()
    sequential_results = []
    for i, text in enumerate(test_texts):
        print(f"  Processing document {i+1}/{len(test_texts)}...")
        result = await sequential_pipeline.process_text(text)
        sequential_results.append(result)
    sequential_time = time.time() - start_time
    
    print(f"  ✅ Sequential processing completed in {sequential_time:.2f} seconds")
    
    # Parallel processing
    print("\n⚡ Parallel Processing:")
    config = ProcessingConfig(max_concurrent_incidents=3)
    parallel_pipeline = ParallelPIIProcessingPipeline(use_real_api=False, config=config)
    
    start_time = time.time()
    parallel_results = []
    tasks = []
    for i, text in enumerate(test_texts):
        print(f"  Queuing document {i+1}/{len(test_texts)}...")
        task = asyncio.create_task(parallel_pipeline.process_text(text))
        tasks.append(task)
    
    parallel_results = await asyncio.gather(*tasks)
    parallel_time = time.time() - start_time
    
    print(f"  ✅ Parallel processing completed in {parallel_time:.2f} seconds")
    
    # Compare results
    print(f"\n📊 Performance Comparison:")
    print(f"  Sequential time: {sequential_time:.2f}s")
    print(f"  Parallel time: {parallel_time:.2f}s")
    speedup = sequential_time / parallel_time if parallel_time > 0 else 1.0
    print(f"  Speedup: {speedup:.2f}x")
    
    # Verify results are equivalent
    print(f"\n🔍 Result Verification:")
    for i, (seq_result, par_result) in enumerate(zip(sequential_results, parallel_results)):
        seq_processed = seq_result['processed_text']
        par_processed = par_result.processed_text
        
        if seq_processed == par_processed:
            print(f"  ✅ Document {i+1}: Results match")
        else:
            print(f"  ⚠️  Document {i+1}: Results differ")
    
    # Show parallel processing statistics
    print(f"\n📈 Parallel Processing Statistics:")
    for i, result in enumerate(parallel_results):
        if hasattr(result, 'parallel_stats'):
            stats = result.parallel_stats
            print(f"  Document {i+1}:")
            print(f"    Processing time: {stats.get('total_processing_time', 0):.3f}s")
            print(f"    Concurrent operations: {stats.get('concurrent_operations', 0)}")
    
    print(f"\n🎉 Demo completed successfully!")

async def demonstrate_concurrent_incidents():
    """Demonstrate concurrent incident processing"""
    
    print("\n" + "=" * 60)
    print("🔄 Concurrent Incident Processing Demo")
    print("=" * 60)
    
    # Create test incidents
    test_incidents = [
        {
            'id': f'incident_{i}',
            'title': f'Test Incident {i}',
            'description': f'Contact user{i}@example.com for details about issue {i}',
            'summary': f'Incident {i} involving user{i}@example.com'
        }
        for i in range(10)
    ]
    
    print(f"📝 Processing {len(test_incidents)} test incidents...")
    
    # Configure parallel processing
    config = ProcessingConfig(max_concurrent_incidents=5)
    parallel_pipeline = ParallelPIIProcessingPipeline(use_real_api=False, config=config)
    
    # Process incidents concurrently
    start_time = time.time()
    results = await parallel_pipeline.process_multiple_incidents(test_incidents)
    end_time = time.time()
    
    processing_time = end_time - start_time
    throughput = len(results) / processing_time if processing_time > 0 else 0
    
    print(f"✅ Processed {len(results)}/{len(test_incidents)} incidents")
    print(f"📊 Processing time: {processing_time:.2f} seconds")
    print(f"📊 Throughput: {throughput:.2f} incidents/second")
    
    # Show results summary
    print(f"\n📋 Results Summary:")
    for i, result in enumerate(results):
        print(f"  Incident {i+1}:")
        print(f"    Original length: {len(result.original_text)} chars")
        print(f"    Processed length: {len(result.processed_text)} chars")
        print(f"    Quality score: {result.quality_metrics.get('overall_quality_score', 0):.3f}")
        print(f"    Validation issues: {result.validation_issues}")

async def main():
    """Main demo function"""
    
    try:
        await demonstrate_parallel_processing()
        await demonstrate_concurrent_incidents()
        
        print(f"\n🎯 Key Benefits of Parallel Processing:")
        print(f"  • Faster processing of multiple documents")
        print(f"  • Better resource utilization")
        print(f"  • Configurable concurrency limits")
        print(f"  • Automatic error handling and recovery")
        print(f"  • Consistent results with sequential processing")
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
