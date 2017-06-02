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
            // TODO uncomment below to test the method and replace null with proper value

            string token = JoseUtils.EncodeRS256("2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a4d4949457051494241414b4341514541733959534d3878455974585261506939384162425948654e3748546b7a5677424a75416843324c532f425769397744460a596d786b7479504d55477476566a354b5075574d377835336c54377343564b4775426379634e6845575848653154323354597950506d6349426255313554344f0a5a617a462f473570677a756263493130357174433778683556436938377962766a4869637254464d68646244386438306c434855635662674e37646f475731340a6d4f324d596d31496a457657344e685a7643302f41325043754343774b737a3836357a774d3768353575514f6333514b6333764f2f78664c54357063366843320a66637a3479364759554e475632752b565771642b66694b4841546a2b6b436f355458664a6f616932647a477444594645672f704c6f68616d4d62704a4d64486b0a596551526f624452554942396863426c2b41666b6c6275505a4b5a412b374e6134356a616951494441514142416f494241514342636f6772724d39553757414e0a5657387a42556e5137483347524f596c52434b34487744714e7a707a7067646d454c4945424d34435863784633752b4866744c6d72306c6848656371454e374b0a58784d47452f79453663645a4d76515a5070466853746f5a4b77544652776b436545625976534c4f62354f586d534a7352415a767537733061384e35357445490a7646675748774e34543149727a4d6e436f7334774371486d3634663930647668334271742f574737525667573856474f47576e674a565a755230685230504f300a69484c5247655a6e6430486251767a7a35516941645674454e4c4a523465724e4d3762456d4c54656c6a6c5459305362784f454b34766a473674546547654c700a34627a622b567965397367592f50444b48303875373542645037466e45472b6d456e765767723469552f58464148717736426e4958773565624e584e48536d590a4b2f4f4f59504542416f4742414d7843527333574b6c433776754c57647061347345616e6a527a70467248324556732f506e6b4358682f756469385a6134556a0a41797841433747544e50534c6234595761697839305a62556c324e41535a4c326f4b364b3377746f655a42386337716d566e4867652b69564b455061372f72730a4c6e795235644e2f63543777652f4365487663323367656d5a31546c444a666d6b6e50414b66696d4e5563775674495867535a51486c4452416f4742414f466b0a4369466a616a51725a75355059546d456953585763314431682f6d447a7676366f5a776f2f70743431686b55694e6b5351766f3839516e5948654f2b624c47770a367241646b6a2b5442502b4544564c32665a456c6b596878334c454e4e4878644261684a3752556e6837456f3948624848724c386673574a6f6c46432f6566410a736c4779737747335947687537334637685970657437616f73454246542f6a553062734d59687735416f47414b684e4d2b6f477658636f4f33444e4a596d72520a42507a6d754a6e624c76563952637156562b41412b35726e68585137446358556c587a723637786a49437a4934466f6c724e794f472f2f5733333853714d39630a386864784d71786d766a696b726b497464472f466c6e65445039634e7343614f764f4a67385678444f362f5747413636576a70584b6b5241374e2f783543682b0a36704566464456497245317331514936664758736d4d45436759454131626d6f525972677a59474f68464976626e7734465049717655316d562f7465446544570a324a36692b4568344e4b59644d6b47333031523051355a306d563462386339436243684f5977794667386e7a58495579417133754e38564973586446477479570a6e634d6b46706736656f724d62636c5a576635474e416a554b3178734b684f32772f50412f4e4b6e6a38414b4f3845576d32512f7275783833535563745763520a546435724e6a6b43675945416b7856715a3431366c623338317564496a737230542f4866496f64762f4363796e724b787263475978416c6c58626a71744b794f0a334c4e43416863746d4b5533413648514f33302b694f77476165303344646e6b4d704c6a6f31524d4139394b5456424243314b776842763333386d6a503651440a6163433767304a6651434b41306148704f68436e395a707076393875486a474a675237642b753151633470464d68685a6d747a314d65513d0a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d0a");
            int account = 3;
            string user = "test";
            string pass = "test";
            int id = 243;
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