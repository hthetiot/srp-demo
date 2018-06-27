
var expect = require('chai').expect;
var SrpClient = require('../../lib/srp').SrpClient;

describe('srp-demo', () => {
  beforeEach((done) => {
     done();        
  });
  describe('SrpClient', () => {
      it('setPassword', (done) => {
    		  var srp = new SrpClient();
    		  srp.setPassword('password');
    		  expect(srp.data.srp_status).to.equal('Authentication succeeded');
          done();
      });
  });
});
