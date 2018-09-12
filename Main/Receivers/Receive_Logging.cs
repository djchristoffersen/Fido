/*
*
*  Copyright 2015 Netflix, Inc.
*
*     Licensed under the Apache License, Version 2.0 (the "License");
*     you may not use this file except in compliance with the License.
*     You may obtain a copy of the License at
*
*         http://www.apache.org/licenses/LICENSE-2.0
*
*     Unless required by applicable law or agreed to in writing, software
*     distributed under the License is distributed on an "AS IS" BASIS,
*     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*     See the License for the specific language governing permissions and
*     limitations under the License.
*
*/

using Fido_Main.Main.Detectors;

namespace Fido_Main.Main.Receivers
{
    public abstract class Detector
    {
        public string Name { get; set; }
        public string Vendor { get; set; }
        public string  DefaultServer { get; set; }
        public string DefaultFile { get; set; }
        public bool ParameterTest { get; set; }

        public abstract void DoWork();
        
    }

    public abstract class AntiVirus : Detector
    {

    }

    public class SophosAnti : AntiVirus
    {
        public override void DoWork()
        {
            Sophos.ReadLogs(DefaultServer, DefaultFile);
        }
    }

    public class TrendAnti : AntiVirus
    {
        public override void DoWork()
        {
        }
    }

    public class SymantecAnti : AntiVirus
    {
        public override void DoWork()
        {
        }
    }

    static class Receive_Logging
  {
        //DirectorToEngine is the handler for logging based detectors. It is designed
        //to initiate and direct configured logged based detectors to their respective module
        public static void DirectToEngine(Detector detector)
        {

            detector.DoWork();
        }

  }
}
