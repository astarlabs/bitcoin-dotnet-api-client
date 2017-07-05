/* 
 * Bitcoin API
 *
 * Blockchain Facilities
 *
 * OpenAPI spec version: 2.0.0
 * Contact: contato@astarlabs.com
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */

using System;
using System.IO;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Reflection;
using RestSharp;
using NUnit.Framework;

using AStar.Client;
using AStar.Api;
using AStar.Model;
using AStar.Util;

namespace AStar.Test
{
    /// <summary>
    ///  Class for testing SearchApi
    /// </summary>
    /// <remarks>
    /// This file is automatically generated by Swagger Codegen.
    /// Please update the test case below to test the API endpoint.
    /// </remarks>
    [TestFixture]
    public class SearchApiTests
    {
        private SearchApi instance;

        /// <summary>
        /// Setup before each unit test
        /// </summary>
        [SetUp]
        public void Init()
        {
            instance = new SearchApi();
        }

        /// <summary>
        /// Clean up after each unit test
        /// </summary>
        [TearDown]
        public void Cleanup()
        {

        }

        /// <summary>
        /// Test an instance of SearchApi
        /// </summary>
        [Test]
        public void InstanceTest()
        {
            // TODO uncomment below to test 'IsInstanceOfType' SearchApi
            //Assert.IsInstanceOfType(typeof(SearchApi), instance, "instance is a SearchApi");
        }

        
        /// <summary>
        /// Test SearchByAPIID
        /// </summary>
        [Test]
        public void SearchByAPIIDTest()
        {
            string token = Token.sign("2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a4d4949456f67494241414b434151454178624a56514f6561724e4c334b2b5a3549784947436d7454614c342b70356f31527536326d416d6a6343577431636a660a4c6f303161386c776c3357307a5564776b7049475239354159556e4c795534493269694e4145696e316344383451774a616869424b75347256457758756642360a447977446747776233355438584e416143635467636667524c704f6f78684d49446b32686d6c61736869622f32424b412b6e6e59567679746b3061552f5258510a71495653572f5874624d5371746c6b3133345454644b4432464a70796b386e42665035716245533651494957472f465842727a386758724d5341334a644b425a0a4176594d554956594d686e387575326b676d325537386b555065335777544b65797a33584969613069324a62597558766179563742555253392b3051376268350a56366b6c386c6e6b577a665a344d616268724b387167596663556157495748472b6b546d4477494441514142416f4942414130533541787378492f56533738390a654a6c58496373696d647439615574514b57484e65346e476157614c4e316e42395042784b6930386e784f46467a5855475a2b33784736515268576f2b6138510a57416d465550334a30442b55696153675653634e413833412f6d434f763672754f6b51796c7643784e5936746e5a724e73457368462b367868774662686e66430a336d2b44747349734a5443683935316b6139386b6d36663141633252615a624a2b773445323965767348464336316b567a386478576d6b62644c6f72374b64450a493336766e4c6362767a6a77447357704931796238526d52476a4870385475384c3568795630544e6a2b4461447a5069744652317a2b577942666376593442430a425a47593177316c6d566934396944352b436d42786c4e706c6e5a352f3576646e4577373758437866414f7955734c6b326a412f4c386e4375584e67485050640a655a462b636945436759454136536a354d6379744b33386e547554314f7144796b684c6b72784439516b36627271446b392f2f77624738755a3762394d306c610a4243716b36446451665370484230307130794454624d67575542305135626e6f5248444d435a357a2f7264573970556137636c696754557661706b30714c64790a597261444d52302f312f5974784c765478704b634563565554654b555358495630524152746f384e45684134534676695365476c4b366b4367594541325241490a4d5471594957566d5445422b65706a766767353664797a5646377a366472786936546668515177514b4f6d35577675314a7339675a54336541656e6f483441590a576e31387877707a7433303848777062394c756573425a453632586e5a31636651796e68634c7037797779666159776a7661554c4d2f737048435063654e757a0a5474594d6f4346466b3152344c6d3050504567416c2f4a734333757067384c4263527431567663436759413053313951337849372f6b486e76517950674d66480a4958757646455670574d34734a6151565234383645746d366f313034346f76524157754a4e646255712b5851616d74666653354f614c597763385231636650350a58623831725264684775666a57462f34303046487235455a2f4a4447417063694d734e4d4162357642715550536631657655564a36784e55674b7733714f48680a795250662b5565364e4738624d3569576234696e4f514b42674163484e3979774d77445230624169586e59467761754b5948692f594e373135583432743155700a314164524a717a4d644933336e485033507633494e516f47307464435249655a6a4a4b395365586c4469394c484a4d6543424e5868542f422b75346a716756340a7336333875386c6c54547754703479616258527661334e587a656d7a3432686f45647956647a5641424f77723539526832484d544447434b7a6f4250724166480a68644d64416f47415a73514b316e72654a4a6c6a59534b677545363037755333306350736b4e79326f566539476b447957656639717744437875507a493331370a51796838684a3368315a2f6a5a353049312b37457072633755656b635564726b46484c72654776437a475530612f3644767a79334b446c35564558664b7a424e0a57767131595057454244796659645234383077487356425054377333724c5576725236415845306d64334f65334a69504471733d0a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d0a");
            int account = 16;
            string user = "test";
            string pass = "test";
            int id = 333;
            var response = instance.SearchByAPIID(token, account, user, pass, id);
            Assert.IsInstanceOf<Transaction> (response, "response is Transaction");
        }
        
        /// <summary>
        /// Test SearchByContent
        /// </summary>
        [Test]
        public void SearchByContentTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //string token = null;
            //int? account = null;
            //string user = null;
            //string pass = null;
            //string content = null;
            //var response = instance.SearchByContent(token, account, user, pass, content);
            //Assert.IsInstanceOf<Transaction> (response, "response is Transaction");
        }
        
        /// <summary>
        /// Test SearchByHash
        /// </summary>
        [Test]
        public void SearchByHashTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //string token = null;
            //int? account = null;
            //string user = null;
            //string pass = null;
            //string hash = null;
            //var response = instance.SearchByHash(token, account, user, pass, hash);
            //Assert.IsInstanceOf<Transaction> (response, "response is Transaction");
        }
        
    }

}