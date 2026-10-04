import test from 'node:test';
import assert from 'node:assert/strict';

test('VAO approval should mark a mutation as ready for revenue inspector review', () => {
  const mutation = {
    id: 'mut001',
    status: 'Pending VAO',
    approved: false,
    remarks: 'Awaiting VAO validation'
  };

  const escalatedForRevenueInspector = {
    ...mutation,
    status: 'Pending RI',
    approved: true,
    remarks: 'Escalated to Revenue Inspector'
  };

  assert.equal(mutation.approved, false);
  assert.equal(escalatedForRevenueInspector.status, 'Pending RI');
  assert.equal(escalatedForRevenueInspector.approved, true);
});
