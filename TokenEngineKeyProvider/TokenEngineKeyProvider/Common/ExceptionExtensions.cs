using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TokenEngineKeyProvider.Common
{
    internal static class ExceptionExtensions
    {
        public static string GetRelevantMessage(this Exception exception)
        {
            var aggregateException = exception as AggregateException;
            if (aggregateException != null)
                return aggregateException.InnerException.GetRelevantMessage();
            return exception.Message;
        }
    }
}
