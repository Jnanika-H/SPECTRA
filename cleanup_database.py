"""
SPECTRA Database Cleanup Script
Deletes all test cases from MongoDB
"""

from pymongo import MongoClient
import sys

def cleanup_database():
    try:
        # Connect to MongoDB
        print("Connecting to MongoDB...")
        client = MongoClient('mongodb://localhost:27017/')
        db = client['spectra']
        
        # Show current counts
        evidence_count = db.evidence.count_documents({})
        reports_count = db.reports.count_documents({})
        feedback_count = db.feedback.count_documents({})
        
        print(f"\n📊 Current Database Status:")
        print(f"   Evidence: {evidence_count} documents")
        print(f"   Reports: {reports_count} documents")
        print(f"   Feedback: {feedback_count} documents")
        
        # Ask for confirmation
        print("\n⚠️  WARNING: This will delete ALL evidence, reports, and feedback!")
        response = input("Are you sure you want to continue? (yes/no): ")
        
        if response.lower() != 'yes':
            print("❌ Cleanup cancelled.")
            return
        
        # Delete all documents
        print("\n🗑️  Deleting all documents...")
        
        result1 = db.evidence.delete_many({})
        print(f"   ✅ Deleted {result1.deleted_count} evidence documents")
        
        result2 = db.reports.delete_many({})
        print(f"   ✅ Deleted {result2.deleted_count} report documents")
        
        result3 = db.feedback.delete_many({})
        print(f"   ✅ Deleted {result3.deleted_count} feedback documents")
        
        # Verify deletion
        print("\n📊 Final Database Status:")
        print(f"   Evidence: {db.evidence.count_documents({})} documents")
        print(f"   Reports: {db.reports.count_documents({})} documents")
        print(f"   Feedback: {db.feedback.count_documents({})} documents")
        
        print("\n✅ Database cleanup complete!")
        print("🔄 Refresh your browser (Ctrl+F5) to see changes in SPECTRA UI")
        
        client.close()
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nMake sure:")
        print("1. MongoDB is running (mongod)")
        print("2. pymongo is installed (pip install pymongo)")
        sys.exit(1)

if __name__ == "__main__":
    cleanup_database()
