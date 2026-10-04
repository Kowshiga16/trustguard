import { MongoClient } from 'mongodb';

const client = new MongoClient('mongodb://127.0.0.1:27017');
await client.connect();
const db = client.db('trustguard');

const result = await db.collection('users').updateOne(
  { email: 'vijay@gmail.com' },
  { $set: { 'assignedJurisdiction.taluk': 'Tambaram' } }
);

console.log(JSON.stringify({ matched: result.matchedCount, modified: result.modifiedCount }));

await client.close();
