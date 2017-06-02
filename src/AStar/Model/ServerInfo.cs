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
using System.Linq;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Runtime.Serialization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System.ComponentModel.DataAnnotations;

namespace AStar.Model
{
    /// <summary>
    /// SingleResult
    /// </summary>
    [DataContract]
    public partial class ServerInfo :  IEquatable<ServerInfo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ServerInfo" /> class.
        /// </summary>
        /// <param name="FullAddress">result.</param>
        /// <param name="Host">result.</param>
        /// <param name="Port">result.</param>
        /// <param name="Version">result.</param>
        /// <param name="Protocol">result.</param>
        public ServerInfo(string FullAddress = default(string), string Host = default(string), int? Port = default(int?), string Version = default(string), string Protocol = default(string))
        {
            this.FullAddress = FullAddress;
            this.Host = Host;
            this.Port = Port;
            this.Version = Version;
            this.Protocol = Protocol;
        }
        
        /// <summary>
        /// fulladdress
        /// </summary>
        /// <value>fulladdress</value>
        [DataMember(Name="fulladdress", EmitDefaultValue=false)]
        public string FullAddress { get; set; }
        /// <summary>
        /// host
        /// </summary>
        /// <value>host</value>
        [DataMember(Name="host", EmitDefaultValue=false)]
        public string Host { get; set; }
        /// <summary>
        /// port
        /// </summary>
        /// <value>port</value>
        [DataMember(Name="port", EmitDefaultValue=false)]
        public int? Port { get; set; }
        /// <summary>
        /// version
        /// </summary>
        /// <value>version</value>
        [DataMember(Name="version", EmitDefaultValue=false)]
        public string Version { get; set; }
        /// <summary>
        /// protocol
        /// </summary>
        /// <value>protocol</value>
        [DataMember(Name="protocol", EmitDefaultValue=false)]
        public string Protocol { get; set; }
  
        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public string ToJson()
        {
            return JsonConvert.SerializeObject(this, Formatting.Indented);
        }

        /// <summary>
        /// Returns true if objects are equal
        /// </summary>
        /// <param name="obj">Object to be compared</param>
        /// <returns>Boolean</returns>
        public override bool Equals(object obj)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            return this.Equals(obj as ServerInfo);
        }

        /// <summary>
        /// Returns true if SingleResult instances are equal
        /// </summary>
        /// <param name="other">Instance of SingleResult to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ServerInfo other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.FullAddress == other.FullAddress ||
                    this.FullAddress != null &&
                    this.FullAddress.Equals(other.FullAddress)
                );
        }

        /// <summary>
        /// To validate all properties of the instance
        /// </summary>
        /// <param name="validationContext">Validation context</param>
        /// <returns>Validation Result</returns>
        IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> IValidatableObject.Validate(ValidationContext validationContext)
        {
            yield break;
        }
    }

}
