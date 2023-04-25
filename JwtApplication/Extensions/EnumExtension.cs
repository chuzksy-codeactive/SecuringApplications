using System.ComponentModel;
using System.Reflection;

namespace JwtApplication.Extensions
{
    public static class EnumExtension
    {
        public static string GetDescription(this Enum value)
        {
            FieldInfo fieldInfo = value.GetType().GetField(value.ToString());
            if (fieldInfo == null) return null;
            var attribute = (DescriptionAttribute)fieldInfo.GetCustomAttribute(typeof(DescriptionAttribute));
            return attribute.Description;
        }

        public static int ParseStringToEnum(this string str, Type value)
        {
            var isValid = Enum.TryParse(value, str, true, out var result);

            if (isValid)
            {
                return (int)result;
            }

            throw new ArgumentException($"{str} must be an enumerated type");
        }

        public static List<EnumResult> GetEnumResults<T>(bool useDescriptionValue = false)
        {
            var enumList = new List<EnumResult>();
            foreach (var item in Enum.GetValues(typeof(T)))
            {

                enumList.Add(new EnumResult()
                {
                    Id = (int)item,
                    Name = !useDescriptionValue ? item?.ToString() : GetDescription<T>((T)item),
                });
            }
            return enumList;
        }

        // Get the Description of the enum value by Generic T enum value
        public static string GetDescription<T>(T value)
        {
            return
                value
                    .GetType()
                    .GetMember(value.ToString())
                    .FirstOrDefault()
                    ?.GetCustomAttribute<DescriptionAttribute>()
                    ?.Description
                    ?.ToString();
        }
    }

    public class EnumResult
    {
        public int Id { get; set; }
        public string Name { get; set; }
    }
}
