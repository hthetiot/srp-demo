
var expect = require('chai').expect;
var SrpClient = require('../../lib/srp').SrpClient;
var utilsBigInt = require('../../lib/utils/big-int');

describe('SrpClient', () => {
  beforeEach((done) => {
     done();        
  });
  describe('Demo', () => {
      var srp = new SrpClient();
      srp.setUsername('test');
      srp.setPassword('password');

      it('checkPassword failure', (done) => {
          expect(srp.checkPassword('passwordbad')).to.equal(false);
    		  expect(srp.data.srp_status).to.equal('Authentication failed - try again');
          done();
      });

      it('checkPassword success', (done) => {
          expect(srp.checkPassword('password')).to.equal(true);
          expect(srp.data.srp_status).to.equal('Authentication succeeded');
          done();
      });

      it('checkToken success', (done) => {
          expect(srp.checkToken(srp.data.srp_Ss)).to.equal(true);
          expect(srp.checkToken(srp.data.srp_Sc)).to.equal(true);
          expect(srp.data.srp_status).to.equal('Authentication succeeded');
          done();
      });
  });

  describe('Client/Server Workflow', () => {

      var srpServer = new SrpClient({
        server: true,
        username: 'test',
        password: 'password',
        salt: utilsBigInt.bigInt2radix(utilsBigInt.randomBigInt(10), 10),
        k: utilsBigInt.randomBigInt(10)
      });

      var srpClient = new SrpClient({
        client: true,
        username: 'test',
        params: srpServer.data.params,
        radix: srpServer.data.srp_radixb,
        N: srpServer.data.srp_N,
        g: srpServer.data.srp_g,
        salt: srpServer.data.srp_salt,
        k: srpServer.data.srp_k
      });

      console.log('srp_A', srpClient.data.srp_A);
      srpServer.setServerA(srpClient.data.srp_A);

      console.log('srp_u', srpServer.data.srp_u);
      console.log('srp_B', srpServer.data.srp_B);
      srpClient.setClientBu(srpServer.data.srp_B, srpServer.data.srp_u);

      console.log('srp_Sc', srpClient.data.srp_Sc);
      console.log('srp_Ss', srpServer.data.srp_Ss);


      it('checkPassword failure', (done) => {
          expect(srpClient.checkPassword('passwordbad', srpServer.data.srp_Ss)).to.equal(false);
          expect(srpClient.data.srp_status).to.equal('Authentication failed - try again');
          done();
      });

      it('checkPassword success', (done) => {
          expect(srpClient.checkPassword('password', srpServer.data.srp_Ss)).to.equal(true);
          expect(srpClient.data.srp_status).to.equal('Authentication succeeded');
          done();
      });

      it('checkToken success', (done) => {
          expect(srpClient.checkToken(srpClient.data.srp_Sc)).to.equal(true);
          expect(srpClient.data.srp_status).to.equal('Authentication succeeded');
          done();
      });
  });
});
