import { MongoClient } from 'mongodb';

const client = new MongoClient('mongodb://127.0.0.1:27017');
await client.connect();
const db = client.db('trustguard');

const vijay = await db.collection('users').findOne({ email: 'vijay@gmail.com' });
console.log('vijay user:', JSON.stringify(vijay?.assignedJurisdiction));

const mutations = await db.collection('mutations').find({ status: 'Pending RI' }).toArray();
console.log('pending RI mutations:', JSON.stringify(mutations.map(m => ({ id: m.id, status: m.status, villageName: m.villageName, approved: m.approved, requestedByName: m.requestedByName })), null, 2));

await client.close();

const loginRes = await fetch('http://localhost:3000/api/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ userId: vijay.id, customDevice: 'Admin_Device' })
});

const loginJson = await loginRes.json();
console.log('login:', JSON.stringify(loginJson));

if (loginJson?.session?.id) {
  const mutRes = await fetch('http://localhost:3000/api/mutations', {
    headers: { Authorization: loginJson.session.id }
  });

  const mutJson = await mutRes.json();
  console.log('mutations response:', JSON.stringify(mutJson, null, 2));
}
